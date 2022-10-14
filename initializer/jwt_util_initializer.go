package initializer

import (
	"github.com/Macrow/auth-go-sdk"
	"github.com/Macrow/auth-go-sdk/config"
	"github.com/go-redis/redis/v9"
	"github.com/golang-jwt/jwt/v4"
	"strings"
)

type JwtUtilOption func(util *auth.JwtUtil)

func WithRedisConfig(config config.Redis) JwtUtilOption {
	if len(config.Address) == 0 {
		panic("redis地址配置错误")
	}
	return func(util *auth.JwtUtil) {
		util.Config.Redis.Address = config.Address
		util.Config.Redis.Db = config.Db
		util.Config.Redis.Password = config.Password

		util.Config.IsCluster = strings.Contains(config.Address, ",")
		if util.RedisIsCluster {
			addressArray := strings.Split(config.Address, ",")
			util.RedisClusterClient = redis.NewClusterClient(&redis.ClusterOptions{
				Addrs:    addressArray,
				Password: config.Password,
			})
		} else {
			util.RedisClient = redis.NewClient(&redis.Options{
				Addr:     config.Address,
				DB:       config.Db,
				Password: config.Password,
			})
		}
	}
}

func WithJwtConfig(config config.Jwt) JwtUtilOption {
	if len(config.PublicKey) == 0 || len(config.PrivateKey) == 0 {
		panic("RSA秘钥对配置错误")
	}
	if len(config.Prefix) == 0 {
		config.Prefix = auth.DefaultCachePrefix
	}
	if len(config.CacheSplitter) == 0 {
		config.CacheSplitter = auth.DefaultCacheSplitter
	}
	if len(config.Issuer) == 0 {
		config.Issuer = auth.DefaultIssuer
	}
	if config.ExpireInMinutes <= 0 {
		config.ExpireInMinutes = -1
	}
	return func(util *auth.JwtUtil) {
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

func NewJwtUtil(options ...JwtUtilOption) *auth.JwtUtil {
	jwtUtil := &auth.JwtUtil{}
	for _, opt := range options {
		opt(jwtUtil)
	}
	return jwtUtil
}
