package auth

import (
	"github.com/go-redis/redis/v9"
	"github.com/golang-jwt/jwt/v4"
	"strings"
)

type JwtUtilOption func(util *JwtUtil)

func WithRedisConfig(config RedisConfig) JwtUtilOption {
	if len(config.Address) == 0 {
		panic("redis地址配置错误")
	}
	return func(util *JwtUtil) {
		util.config.RedisConfig = RedisConfig{
			Address:  config.Address,
			Db:       config.Db,
			Password: config.Password,
		}
		util.redisIsCluster = strings.Contains(config.Address, ",")
		if util.redisIsCluster {
			addressArray := strings.Split(config.Address, ",")
			util.redisClusterClient = redis.NewClusterClient(&redis.ClusterOptions{
				Addrs:    addressArray,
				Password: config.Password,
			})
		} else {
			util.redisClient = redis.NewClient(&redis.Options{
				Addr:     config.Address,
				DB:       config.Db,
				Password: config.Password,
			})
		}
	}
}

func WithJwtConfig(config JwtConfig) JwtUtilOption {
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
	return func(util *JwtUtil) {
		util.config.JwtConfig = JwtConfig{
			Prefix:          config.Prefix,
			CacheSplitter:   config.CacheSplitter,
			Issuer:          config.Issuer,
			ExpireInMinutes: config.ExpireInMinutes,
			PublicKey:       config.PublicKey,
			PrivateKey:      config.PrivateKey,
		}
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

func NewJwtUtil(options ...JwtUtilOption) *JwtUtil {
	jwtUtil := &JwtUtil{}
	for _, opt := range options {
		opt(jwtUtil)
	}
	return jwtUtil
}
