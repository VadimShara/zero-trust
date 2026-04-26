package redis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	rdb "github.com/redis/go-redis/v9"

	"github.com/zero-trust/zero-trust-auth/services/token/internal/entities"
	"github.com/zero-trust/zero-trust-auth/services/token/internal/port"
	pkgerrors "github.com/zero-trust/zero-trust-auth/toolkit/pkg/errors"
)

type AccessTokenStore struct {
	client *rdb.Client
}

var _ port.AccessTokenStore = (*AccessTokenStore)(nil)

func NewAccessTokenStore(client *rdb.Client) *AccessTokenStore {
	return &AccessTokenStore{client: client}
}

// key: token:access:{sha256(raw)}  TTL 15m
func (s *AccessTokenStore) Save(ctx context.Context, raw string, t *entities.AccessToken, ttl time.Duration) error {
	data, err := json.Marshal(t)
	if err != nil {
		return err
	}
	return s.client.Set(ctx, accessKey(raw), data, ttl).Err()
}

func (s *AccessTokenStore) Get(ctx context.Context, raw string) (*entities.AccessToken, error) {
	val, err := s.client.Get(ctx, accessKey(raw)).Result()
	if err != nil {
		if errors.Is(err, rdb.Nil) {
			return nil, pkgerrors.ErrNotFound
		}
		return nil, err
	}
	var t entities.AccessToken
	if err := json.Unmarshal([]byte(val), &t); err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *AccessTokenStore) Delete(ctx context.Context, raw string) error {
	return s.client.Del(ctx, accessKey(raw)).Err()
}

func accessKey(raw string) string {
	return fmt.Sprintf("token:access:%s", hashRaw(raw))
}

func hashRaw(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}
