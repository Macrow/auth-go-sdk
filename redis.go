package auth

import (
	"context"
	"github.com/go-redis/redis/v9"
	"strings"
)

var (
	RedisIsCluster     *bool
	RedisClient        *redis.Client
	RedisClusterClient *redis.ClusterClient
)

func ClearRedisCachesByKeyPattern(ctx context.Context, redisAddress string, db int, password string, keyPattern string) {
	initRedisClient(redisAddress, db, password)
	if len(keyPattern) > 0 {
		if *RedisIsCluster {
			// 如果是redis集群，需要遍历master节点才能使用keys进行模糊匹配
			err := RedisClusterClient.ForEachMaster(ctx, func(ctx context.Context, client *redis.Client) error {
				clearRedisByKeyPattern(ctx, client, keyPattern)
				return nil
			})
			panic(err)
		} else {
			clearRedisByKeyPattern(ctx, RedisClient, keyPattern)
		}
	}
}

func initRedisClient(redisAddress string, db int, password string) {
	if RedisIsCluster == nil {
		isCluster := strings.Contains(redisAddress, ",")
		RedisIsCluster = &isCluster
		if isCluster {
			address := strings.Split(redisAddress, ",")
			RedisClusterClient = redis.NewClusterClient(&redis.ClusterOptions{
				Addrs:    address,
				Password: password,
			})
		} else {
			RedisClient = redis.NewClient(&redis.Options{
				Addr:     redisAddress,
				DB:       db,
				Password: password,
			})
		}
	}
}
