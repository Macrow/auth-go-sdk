package auth

import (
	"context"
	"github.com/go-redis/redis/v8"
	"github.com/go-redis/redis_rate/v9"
	"github.com/golang-jwt/jwt/v4"
	"strings"
)

type JwtUtilOption func(util *RedisJwtUtil)

func WithRedisConfig(config Redis) JwtUtilOption {
	if len(config.Address) == 0 {
		panic("redis地址配置错误")
	}
	return func(util *RedisJwtUtil) {
		util.Config.Redis.Address = config.Address
		util.Config.Redis.Db = config.Db
		util.Config.Redis.Password = config.Password

		if util.IsRedisCluster() {
			addressArray := strings.Split(config.Address, ",")
			util.RedisClusterClient = redis.NewClusterClient(&redis.ClusterOptions{
				Addrs:    addressArray,
				Password: config.Password,
			})
			util.RateLimiter = redis_rate.NewLimiter(util.RedisClusterClient)
		} else {
			util.RedisClient = redis.NewClient(&redis.Options{
				Addr:     config.Address,
				DB:       config.Db,
				Password: config.Password,
			})
			util.RateLimiter = redis_rate.NewLimiter(util.RedisClient)
		}
	}
}

func WithJwtConfig(config Jwt) JwtUtilOption {
	if len(config.PublicKey) == 0 || len(config.PrivateKey) == 0 {
		panic("RSA秘钥对配置错误")
	}
	if len(config.Prefix) == 0 {
		config.Prefix = DefaultCachePrefix
	}
	if len(config.CacheSplitter) == 0 {
		config.CacheSplitter = DefaultCacheSplitter
	}
	if len(config.Issuer) == 0 {
		config.Issuer = DefaultIssuer
	}
	if config.ExpireInMinutes <= 0 {
		config.ExpireInMinutes = -1
	}
	return func(util *RedisJwtUtil) {
		util.Config.Jwt.Prefix = config.Prefix
		util.Config.Jwt.CacheSplitter = config.CacheSplitter
		util.Config.Jwt.Issuer = config.Issuer
		util.Config.Jwt.ExpireInMinutes = config.ExpireInMinutes
		util.Config.Jwt.PublicKey = config.PublicKey
		util.Config.Jwt.PrivateKey = config.PrivateKey

		PrivateKey, err := jwt.ParseRSAPrivateKeyFromPEM(config.PrivateKey)
		if err != nil {
			panic(err)
		}
		util.PrivateKey = PrivateKey

		PublicKey, err := jwt.ParseRSAPublicKeyFromPEM(config.PublicKey)
		if err != nil {
			panic(err)
		}
		util.PublicKey = PublicKey
	}
}

func NewRedisJwtUtil(ctx context.Context, options ...JwtUtilOption) *RedisJwtUtil {
	util := &RedisJwtUtil{Ctx: ctx}
	for _, opt := range options {
		opt(util)
	}
	if (util.RedisClient == nil && util.RedisClusterClient == nil) || util.RateLimiter == nil {
		panic("请配置redis参数")
	}
	return util
}
