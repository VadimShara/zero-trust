package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

func (c *TrustCache) GetFails(ctx context.Context, userID uuid.UUID) (int64, error) {
	val, err := c.client.Get(ctx, fmt.Sprintf("trust:fails:%s", userID)).Int64()
	if err != nil {
		return 0, nil
	}
	return val, nil
}

func (c *TrustCache) IncrFails(ctx context.Context, userID uuid.UUID) (int64, error) {
	return c.incrWithTTL(ctx, fmt.Sprintf("trust:fails:%s", userID), c.failTTL)
}

func (c *TrustCache) ResetFails(ctx context.Context, userID uuid.UUID) error {
	return c.client.Del(ctx, fmt.Sprintf("trust:fails:%s", userID)).Err()
}

func (c *TrustCache) SetFails(ctx context.Context, userID uuid.UUID, count int64, ttl time.Duration) error {
	return c.client.Set(ctx, fmt.Sprintf("trust:fails:%s", userID), count, ttl).Err()
}

func (c *TrustCache) GetIPFails(ctx context.Context, ipHash string) (int64, error) {
	val, err := c.client.Get(ctx, fmt.Sprintf("trust:fails:ip:%s", ipHash)).Int64()
	if err != nil {
		return 0, nil
	}
	return val, nil
}

func (c *TrustCache) IncrIPFails(ctx context.Context, ipHash string) (int64, error) {
	return c.incrWithTTL(ctx, fmt.Sprintf("trust:fails:ip:%s", ipHash), c.ipFailTTL)
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
