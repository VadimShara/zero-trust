package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

const failTTL = 15 * time.Minute // sliding window per Redis key schema

// key: trust:fails:{userID}  TTL 15m  — per-user fail counter
func (c *TrustCache) IncrFails(ctx context.Context, userID uuid.UUID) (int64, error) {
	return c.incrWithTTL(ctx, fmt.Sprintf("trust:fails:%s", userID), failTTL)
}

// key: trust:fails:ip:{ipHash}  TTL 15m  — per-IP anonymous check counter
func (c *TrustCache) IncrIPFails(ctx context.Context, ipHash string) (int64, error) {
	return c.incrWithTTL(ctx, fmt.Sprintf("trust:fails:ip:%s", ipHash), failTTL)
}

func (c *TrustCache) incrWithTTL(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	pipe := c.client.Pipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, err
	}
	return incr.Val(), nil
}
