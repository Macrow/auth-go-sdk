package auth

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"github.com/go-redis/redis/v8"
	"github.com/go-redis/redis_rate/v9"
	"github.com/golang-jwt/jwt/v4"
	"strconv"
	"strings"
	"time"
)

type RedisJwtUtil struct {
	Ctx                context.Context
	Config             JwtUtilConfig
	RedisClient        *redis.Client
	RedisClusterClient *redis.ClusterClient
	PublicKey          *rsa.PublicKey
	PrivateKey         *rsa.PrivateKey
	RateLimiter        *redis_rate.Limiter
}

func (j *RedisJwtUtil) IsRedisCluster() bool {
	return strings.Contains(j.Config.Address, ",")
}

func (j *RedisJwtUtil) GetUserJwtCacheKey(id, did string, iat float64) string {
	return strings.Join([]string{j.Config.Prefix, id, did + DidAndIatJoiner + strconv.Itoa(int(iat))}, j.Config.CacheSplitter)
}

func (j *RedisJwtUtil) GetUserDidJwtCacheKeyPrefix(id, did string) string {
	return strings.Join([]string{j.Config.Prefix, id, did}, j.Config.CacheSplitter)
}

func (j *RedisJwtUtil) GetUserJwtCacheKeyPrefix(id string) string {
	return strings.Join([]string{j.Config.Prefix, id}, j.Config.CacheSplitter)
}

func (j *RedisJwtUtil) GenerateJwt(id, username, kind, deviceId string, issueAt float64, expireAt float64) (jwtUser *JwtUser, err error) {
	if len(j.Config.Issuer) == 0 {
		j.Config.Issuer = DefaultIssuer
	}
	rawToken := jwt.New(jwt.SigningMethodRS256)
	claims := rawToken.Claims.(jwt.MapClaims)
	claims[JwtTokenClaimsId] = id
	claims[JwtTokenClaimsName] = username
	claims[JwtTokenClaimsKind] = kind
	claims[JwtTokenClaimsDeviceId] = deviceId
	claims[JwtTokenClaimsIssuer] = j.Config.Issuer
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
			Iss:  j.Config.Issuer,
			Iat:  issueAt,
			Exp:  expireAt,
		},
		Token: token,
	}

	return jwtUser, nil
}

func (j *RedisJwtUtil) ValidateJwt(tokenString string) (*JwtUser, error) {
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

func (j *RedisJwtUtil) SignJwtAndSaveToCache(id, name, kind, did string) *JwtUser {
	iat := time.Now()
	var exp int64
	if j.Config.ExpireInMinutes > 0 {
		exp = iat.Add(time.Duration(j.Config.ExpireInMinutes) * time.Minute).Unix()
	} else {
		exp = 0
	}
	jwtUser, err := j.GenerateJwt(id, name, kind, did, float64(iat.Unix()), float64(exp))
	if err != nil {
		panic(err)
	}
	jwtUser.Iat = float64(iat.Unix())

	j.ClearRedisCachesByKeyPattern(j.GetUserDidJwtCacheKeyPrefix(id, did))
	j.SetJwtUser(jwtUser)

	return jwtUser
}

func (j *RedisJwtUtil) CheckJwtIsInCache(jwtUser *JwtUser) bool {
	if jwtUser == nil {
		return false
	}
	key := j.GetUserJwtCacheKey(jwtUser.Id, jwtUser.Did, jwtUser.Iat)
	if j.IsRedisCluster() {
		exists, err := j.RedisClusterClient.Do(j.Ctx, "EXISTS", key).Bool()
		if err != nil {
			panic(err)
		}
		return exists
	} else {
		exists, err := j.RedisClient.Do(j.Ctx, "EXISTS", key).Bool()
		if err != nil {
			panic(err)
		}
		return exists
	}
}

func (j *RedisJwtUtil) DelJwtByUserId(id string) {
	j.ClearRedisCachesByKeyPattern(j.GetUserJwtCacheKeyPrefix(id) + "*")
}

func (j *RedisJwtUtil) DelJwtByUserIdAndDeviceId(id, did string) {
	j.ClearRedisCachesByKeyPattern(j.GetUserDidJwtCacheKeyPrefix(id, did) + "*")
}

func (j *RedisJwtUtil) DelJwtByUserIdAndDeviceIdAndIat(id, did string, iat float64) {
	j.ClearRedisCachesByKeyPattern(j.GetUserJwtCacheKey(id, did, iat) + "*")
}

func (j *RedisJwtUtil) SetJwtUser(jwtUser *JwtUser) {
	j.SetObjInRedis(j.GetUserJwtCacheKey(jwtUser.Id, jwtUser.Did, jwtUser.Iat), jwtUser, j.Config.ExpireInMinutes)
}

func (j *RedisJwtUtil) GetJwtUserByUserId(key string) *JwtUser {
	obj := j.GetObjInRedis(key)
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

func (j *RedisJwtUtil) ClearRedisCachesByKey(key string) {
	if len(key) > 0 {
		if j.IsRedisCluster() {
			_, err := j.RedisClusterClient.Do(j.Ctx, "DEL", key).Result()
			if err != nil {
				panic(err)
			}
		} else {
			_, err := j.RedisClient.Do(j.Ctx, "DEL", key).Result()
			if err != nil {
				panic(err)
			}
		}
	}
}

func (j *RedisJwtUtil) GetObjInRedis(key string) []byte {
	if j.IsRedisCluster() {
		res, err := j.RedisClusterClient.Do(j.Ctx, "GET", key).Result()
		if err != nil {
			panic(err)
		}
		return res.([]byte)
	} else {
		res, err := j.RedisClient.Do(j.Ctx, "GET", key).Result()
		if err != nil {
			panic(err)
		}
		return res.([]byte)
	}
}

func (j *RedisJwtUtil) SetObjInRedis(key string, obj interface{}, expiredInMinutes int) {
	marshal, err := json.Marshal(obj)
	if err != nil {
		panic(err)
	}
	if j.IsRedisCluster() {
		_, err := j.RedisClusterClient.Do(j.Ctx, "SET", key, marshal).Result()
		if err != nil {
			panic(err)
		}
		if expiredInMinutes > 0 {
			_, err = j.RedisClusterClient.Do(j.Ctx, "EXPIRE", key, expiredInMinutes*60).Result()
			if err != nil {
				panic(err)
			}
		}
	} else {
		_, err := j.RedisClient.Do(j.Ctx, "SET", key, marshal).Result()
		if err != nil {
			panic(err)
		}
		if expiredInMinutes > 0 {
			_, err = j.RedisClient.Do(j.Ctx, "EXPIRE", key, expiredInMinutes*60).Result()
			if err != nil {
				panic(err)
			}
		}
	}
}

func (j *RedisJwtUtil) ClearRedisCachesByKeyPattern(keyPattern string) {
	if len(keyPattern) > 0 {
		if j.IsRedisCluster() {
			// 如果是redis集群，需要遍历master节点才能使用keys进行模糊匹配
			err := j.RedisClusterClient.ForEachMaster(j.Ctx, func(ctx context.Context, client *redis.Client) error {
				clearRedisByKeyPattern(ctx, client, keyPattern)
				return nil
			})
			panic(err)
		} else {
			clearRedisByKeyPattern(j.Ctx, j.RedisClient, keyPattern)
		}
	}
}

func (j *RedisJwtUtil) RateLimitBySecond(key string, timesPerSecond int) error {
	res, err := j.RateLimiter.Allow(j.Ctx, key, redis_rate.PerSecond(timesPerSecond))
	if err != nil {
		return err
	}
	if res.Allowed == 0 {
		return RateLimitError
	}
	return nil
}

func (j *RedisJwtUtil) RateLimitByMinute(key string, timesPerMinute int) error {
	res, err := j.RateLimiter.Allow(j.Ctx, key, redis_rate.PerMinute(timesPerMinute))
	if err != nil {
		return err
	}
	if res.Allowed == 0 {
		return RateLimitError
	}
	return nil
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
