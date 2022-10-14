package auth

import (
	"context"
	"crypto/rsa"
	"errors"
	"github.com/go-redis/redis/v9"
	"github.com/golang-jwt/jwt/v4"
	"strconv"
	"strings"
	"time"
)

type JwtUtil struct {
	config             JwtUtilConfig
	redisIsCluster     bool
	redisClient        *redis.Client
	redisClusterClient *redis.ClusterClient
	PublicKey          *rsa.PublicKey
	PrivateKey         *rsa.PrivateKey
}

func (j *JwtUtil) GetUserJwtCacheKey(id, did string, iat float64) string {
	return strings.Join([]string{j.config.Prefix, id, did + DidAndIatJoiner + strconv.Itoa(int(iat))}, j.config.CacheSplitter)
}

func (j *JwtUtil) GetUserDidJwtCacheKeyPrefix(id, did string) string {
	return strings.Join([]string{j.config.Prefix, id, did}, j.config.CacheSplitter)
}

func (j *JwtUtil) GetUserJwtCacheKeyPrefix(id string) string {
	return strings.Join([]string{j.config.Prefix, id}, j.config.CacheSplitter)
}

func (j *JwtUtil) GenerateJwt(id, username, kind, deviceId, issuer string, issueAt float64, expireAt float64) (jwtUser *JwtUser, err error) {
	rawToken := jwt.New(jwt.SigningMethodRS256)
	claims := rawToken.Claims.(jwt.MapClaims)
	claims[JwtTokenClaimsId] = id
	claims[JwtTokenClaimsName] = username
	claims[JwtTokenClaimsKind] = kind
	claims[JwtTokenClaimsDeviceId] = deviceId
	claims[JwtTokenClaimsIssuer] = issuer
	claims[JwtTokenClaimsIssueAt] = issueAt
	claims[JwtTokenClaimsExpireAt] = expireAt

	token, err := rawToken.SignedString(j.PrivateKey)
	if err != nil {
		return nil, err
	}
	jwtUser = &JwtUser{
		RawJwtUser: RawJwtUser{
			Id:   id,
			Name: username,
			Kind: kind,
			Did:  deviceId,
			Iss:  issuer,
			Iat:  issueAt,
			Exp:  expireAt,
		},
		Token: token,
	}

	return jwtUser, nil
}

func (j *JwtUtil) ValidateJwt(tokenString string) (*JwtUser, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if method, ok := t.Method.(*jwt.SigningMethodRSA); !ok || method.Alg() != "RS256" {
			return nil, errors.New(MsgJwtErrFormat)
		}
		return j.PublicKey, nil
	})
	if err != nil || token == nil || !token.Valid {
		return nil, errors.New(MsgJwtErrFormat)
	}
	// 解析令牌并存储为JwtUser格式
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New(MsgJwtErrFormat)
	}

	if claims[JwtTokenClaimsId] == nil ||
		claims[JwtTokenClaimsName] == nil ||
		claims[JwtTokenClaimsKind] == nil ||
		claims[JwtTokenClaimsDeviceId] == nil ||
		claims[JwtTokenClaimsIssuer] == nil ||
		claims[JwtTokenClaimsIssueAt] == nil ||
		claims[JwtTokenClaimsExpireAt] == nil {
		return nil, errors.New(MsgJwtErrVersion)
	}

	jwtUser := &JwtUser{
		RawJwtUser: RawJwtUser{
			Id:   claims[JwtTokenClaimsId].(string),
			Name: claims[JwtTokenClaimsName].(string),
			Kind: claims[JwtTokenClaimsKind].(string),
			Did:  claims[JwtTokenClaimsDeviceId].(string),
			Iss:  claims[JwtTokenClaimsIssuer].(string),
			Iat:  claims[JwtTokenClaimsIssueAt].(float64),
			Exp:  claims[JwtTokenClaimsExpireAt].(float64),
		},
		Token: tokenString,
	}

	return jwtUser, nil
}

func (j *JwtUtil) SignJwtAndSaveToCache(ctx context.Context, id, name, kind, did, iss string) *JwtUser {
	iat := time.Now()
	var exp int64
	if j.config.ExpireInMinutes > 0 {
		exp = iat.Add(time.Duration(j.config.ExpireInMinutes) * time.Minute).Unix()
	} else {
		exp = 0
	}
	jwtUser, err := j.GenerateJwt(id, name, kind, did, iss, float64(iat.Unix()), float64(exp))
	if err != nil {
		panic(err)
	}

	j.ClearRedisCachesByKeyPattern(ctx, j.GetUserDidJwtCacheKeyPrefix(id, did))
	j.SetObjInRedis(ctx, j.GetUserJwtCacheKey(id, did, float64(iat.Unix())), jwtUser, j.config.ExpireInMinutes)

	return jwtUser
}

func (j *JwtUtil) SetObjInRedis(ctx context.Context, key string, obj interface{}, expiredInMinutes int) {
	if j.redisIsCluster {
		_, err := j.redisClusterClient.Do(ctx, "SET", key, obj).Result()
		if err != nil {
			panic(err)
		}
		if expiredInMinutes > 0 {
			_, err = j.redisClusterClient.Do(ctx, "EXPIRE", key, expiredInMinutes*60).Result()
			if err != nil {
				panic(err)
			}
		}
	}
}

func (j *JwtUtil) checkJwtIsInCache(ctx context.Context, jwtUser *JwtUser) bool {
	if jwtUser == nil {
		return false
	}
	key := j.GetUserJwtCacheKey(jwtUser.Id, jwtUser.Did, jwtUser.Iat)
	if j.redisIsCluster {
		exists, err := j.redisClusterClient.Do(ctx, "EXISTS", key).Bool()
		if err != nil {
			panic(err)
		}
		return exists
	} else {
		exists, err := j.redisClient.Do(ctx, "EXISTS", key).Bool()
		if err != nil {
			panic(err)
		}
		return exists
	}
}

func (j *JwtUtil) ClearRedisCachesByKey(ctx context.Context, key string) {
	if len(key) > 0 {
		if j.redisIsCluster {
			_, err := j.redisClusterClient.Do(ctx, "DEL", key).Result()
			if err != nil {
				panic(err)
			}
		} else {
			_, err := j.redisClient.Do(ctx, "DEL", key).Result()
			if err != nil {
				panic(err)
			}
		}
	}
}

func (j *JwtUtil) ClearRedisCachesByKeyPattern(ctx context.Context, keyPattern string) {
	if len(keyPattern) > 0 {
		if j.redisIsCluster {
			// 如果是redis集群，需要遍历master节点才能使用keys进行模糊匹配
			err := j.redisClusterClient.ForEachMaster(ctx, func(ctx context.Context, client *redis.Client) error {
				clearRedisByKeyPattern(ctx, client, keyPattern)
				return nil
			})
			panic(err)
		} else {
			clearRedisByKeyPattern(ctx, j.redisClient, keyPattern)
		}
	}
}

func clearRedisByKeyPattern(ctx context.Context, client *redis.Client, keyPattern string) {
	iter := client.Scan(ctx, 0, keyPattern, 0).Iterator()
	for iter.Next(ctx) {
		_, err := client.Do(ctx, "DEL", iter.Val()).Result()
		if err != nil {
			panic(err)
		}
	}
	if err := iter.Err(); err != nil {
		panic(err)
	}
}
