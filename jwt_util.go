package auth

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"github.com/go-redis/redis/v9"
	"github.com/golang-jwt/jwt/v4"
	"strconv"
	"strings"
	"time"
)

type JwtUtil struct {
	Config             JwtUtilConfig
	RedisClient        *redis.Client
	RedisClusterClient *redis.ClusterClient
	PublicKey          *rsa.PublicKey
	PrivateKey         *rsa.PrivateKey
}

func (j *JwtUtil) IsRedisCluster() bool {
	return strings.Contains(j.Config.Address, ",")
}

func (j *JwtUtil) GetUserJwtCacheKey(id, did string, iat float64) string {
	return strings.Join([]string{j.Config.Prefix, id, did + DidAndIatJoiner + strconv.Itoa(int(iat))}, j.Config.CacheSplitter)
}

func (j *JwtUtil) GetUserDidJwtCacheKeyPrefix(id, did string) string {
	return strings.Join([]string{j.Config.Prefix, id, did}, j.Config.CacheSplitter)
}

func (j *JwtUtil) GetUserJwtCacheKeyPrefix(id string) string {
	return strings.Join([]string{j.Config.Prefix, id}, j.Config.CacheSplitter)
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
	if j.Config.ExpireInMinutes > 0 {
		exp = iat.Add(time.Duration(j.Config.ExpireInMinutes) * time.Minute).Unix()
	} else {
		exp = 0
	}
	jwtUser, err := j.GenerateJwt(id, name, kind, did, iss, float64(iat.Unix()), float64(exp))
	if err != nil {
		panic(err)
	}
	jwtUser.Iat = float64(iat.Unix())

	j.ClearRedisCachesByKeyPattern(ctx, j.GetUserDidJwtCacheKeyPrefix(id, did))
	j.SetJwtUser(ctx, jwtUser)

	return jwtUser
}

func (j *JwtUtil) CheckJwtIsInCache(ctx context.Context, jwtUser *JwtUser) bool {
	if jwtUser == nil {
		return false
	}
	key := j.GetUserJwtCacheKey(jwtUser.Id, jwtUser.Did, jwtUser.Iat)
	if j.IsRedisCluster() {
		exists, err := j.RedisClusterClient.Do(ctx, "EXISTS", key).Bool()
		if err != nil {
			panic(err)
		}
		return exists
	} else {
		exists, err := j.RedisClient.Do(ctx, "EXISTS", key).Bool()
		if err != nil {
			panic(err)
		}
		return exists
	}
}

func (j *JwtUtil) DelJwtByUserId(ctx context.Context, id string) {
	j.ClearRedisCachesByKeyPattern(ctx, j.GetUserJwtCacheKeyPrefix(id)+"*")
}

func (j *JwtUtil) DelJwtByUserIdAndDeviceId(ctx context.Context, id, did string) {
	j.ClearRedisCachesByKeyPattern(ctx, j.GetUserDidJwtCacheKeyPrefix(id, did)+"*")
}

func (j *JwtUtil) SetJwtUser(ctx context.Context, jwtUser *JwtUser) {
	j.SetObjInRedis(ctx, j.GetUserJwtCacheKey(jwtUser.Id, jwtUser.Did, jwtUser.Iat), jwtUser, j.Config.ExpireInMinutes)
}

func (j *JwtUtil) GetJwtUserByUserId(ctx context.Context, key string) *JwtUser {
	obj := j.GetObjInRedis(ctx, key)
	if obj == nil {
		return nil
	}
	var jwtUser JwtUser
	err := json.Unmarshal(obj, &jwtUser)
	if err != nil {
		panic(err)
	}
	return &jwtUser
}

func (j *JwtUtil) ClearRedisCachesByKey(ctx context.Context, key string) {
	if len(key) > 0 {
		if j.IsRedisCluster() {
			_, err := j.RedisClusterClient.Do(ctx, "DEL", key).Result()
			if err != nil {
				panic(err)
			}
		} else {
			_, err := j.RedisClient.Do(ctx, "DEL", key).Result()
			if err != nil {
				panic(err)
			}
		}
	}
}

func (j *JwtUtil) GetObjInRedis(ctx context.Context, key string) []byte {
	if j.IsRedisCluster() {
		res, err := j.RedisClusterClient.Do(ctx, "GET", key).Result()
		if err != nil {
			panic(err)
		}
		return res.([]byte)
	} else {
		res, err := j.RedisClient.Do(ctx, "GET", key).Result()
		if err != nil {
			panic(err)
		}
		return res.([]byte)
	}
}

func (j *JwtUtil) SetObjInRedis(ctx context.Context, key string, obj interface{}, expiredInMinutes int) {
	marshal, err := json.Marshal(obj)
	if err != nil {
		panic(err)
	}
	if j.IsRedisCluster() {
		_, err := j.RedisClusterClient.Do(ctx, "SET", key, marshal).Result()
		if err != nil {
			panic(err)
		}
		if expiredInMinutes > 0 {
			_, err = j.RedisClusterClient.Do(ctx, "EXPIRE", key, expiredInMinutes*60).Result()
			if err != nil {
				panic(err)
			}
		}
	} else {
		_, err := j.RedisClient.Do(ctx, "SET", key, marshal).Result()
		if err != nil {
			panic(err)
		}
		if expiredInMinutes > 0 {
			_, err = j.RedisClient.Do(ctx, "EXPIRE", key, expiredInMinutes*60).Result()
			if err != nil {
				panic(err)
			}
		}
	}
}

func (j *JwtUtil) ClearRedisCachesByKeyPattern(ctx context.Context, keyPattern string) {
	if len(keyPattern) > 0 {
		if j.IsRedisCluster() {
			// 如果是redis集群，需要遍历master节点才能使用keys进行模糊匹配
			err := j.RedisClusterClient.ForEachMaster(ctx, func(ctx context.Context, client *redis.Client) error {
				clearRedisByKeyPattern(ctx, client, keyPattern)
				return nil
			})
			panic(err)
		} else {
			clearRedisByKeyPattern(ctx, j.RedisClient, keyPattern)
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
