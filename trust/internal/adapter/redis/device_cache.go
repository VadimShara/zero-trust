package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

const deviceSetTTL = 90 * 24 * time.Hour

func (c *TrustCache) GetDeviceSet(ctx context.Context, userID uuid.UUID) ([]string, error) {
	key := fmt.Sprintf("trust:devices:%s", userID)
	return c.client.SMembers(ctx, key).Result()
}

func (c *TrustCache) AddDevice(ctx context.Context, userID uuid.UUID, hash string) error {
	key := fmt.Sprintf("trust:devices:%s", userID)
	pipe := c.client.Pipeline()
	pipe.SAdd(ctx, key, hash)
	pipe.Expire(ctx, key, deviceSetTTL)
	_, err := pipe.Exec(ctx)
	return err
}
