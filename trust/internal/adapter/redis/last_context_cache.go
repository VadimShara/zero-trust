package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	rdb "github.com/redis/go-redis/v9"

	"github.com/zero-trust/zero-trust-auth/trust/internal/entities"
	"github.com/zero-trust/zero-trust-auth/trust/internal/cases"
	pkgerrors "github.com/zero-trust/zero-trust-auth/toolkit/pkg/errors"
)

// TrustCache implements cases.TrustCache. Methods are spread across the four
// Redis adapter files — all in the same package.
type TrustCache struct {
	client *rdb.Client
}

var _ cases.TrustCache = (*TrustCache)(nil)

func NewTrustCache(client *rdb.Client) *TrustCache {
	return &TrustCache{client: client}
}

// key: trust:last:{userID}  TTL 30d
func (c *TrustCache) GetLastContext(ctx context.Context, userID uuid.UUID) (*entities.TrustContext, error) {
	key := fmt.Sprintf("trust:last:%s", userID)
	val, err := c.client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, rdb.Nil) {
			return nil, pkgerrors.ErrNotFound
		}
		return nil, err
	}
	var tc entities.TrustContext
	if err := json.Unmarshal([]byte(val), &tc); err != nil {
		return nil, err
	}
	return &tc, nil
}

func (c *TrustCache) SetLastContext(ctx context.Context, userID uuid.UUID, tc *entities.TrustContext, ttl time.Duration) error {
	key := fmt.Sprintf("trust:last:%s", userID)
	data, err := json.Marshal(tc)
	if err != nil {
		return err
	}
	return c.client.Set(ctx, key, data, ttl).Err()
}
