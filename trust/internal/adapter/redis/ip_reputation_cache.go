package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	rdb "github.com/redis/go-redis/v9"

	"github.com/zero-trust/zero-trust-auth/trust/internal/cases"
	pkgerrors "github.com/zero-trust/zero-trust-auth/toolkit/pkg/errors"
)

// IPRepCache is a thin Redis cache for IPInfo, consumed by the httpadapter
// IPReputationClient. It is a separate struct from TrustCache so the http
// adapter can depend on a minimal interface rather than the full cache.
type IPRepCache struct {
	client *rdb.Client
}

func NewIPRepCache(client *rdb.Client) *IPRepCache {
	return &IPRepCache{client: client}
}

// key: trust:ip:{ipHash}  TTL 1h
func (c *IPRepCache) Get(ctx context.Context, ipHash string) (*cases.IPInfo, error) {
	key := fmt.Sprintf("trust:ip:%s", ipHash)
	val, err := c.client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, rdb.Nil) {
			return nil, pkgerrors.ErrNotFound
		}
		return nil, err
	}
	var info cases.IPInfo
	if err := json.Unmarshal([]byte(val), &info); err != nil {
		return nil, err
	}
	return &info, nil
}

func (c *IPRepCache) Set(ctx context.Context, ipHash string, info *cases.IPInfo, ttl time.Duration) error {
	key := fmt.Sprintf("trust:ip:%s", ipHash)
	data, err := json.Marshal(info)
	if err != nil {
		return err
	}
	return c.client.Set(ctx, key, data, ttl).Err()
}
