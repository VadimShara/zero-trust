package redis

import (
	"context"
	"errors"
	"fmt"
	"time"

	rdb "github.com/redis/go-redis/v9"

	"github.com/zero-trust/zero-trust-auth/services/idpadapter/internal/port"
	pkgerrors "github.com/zero-trust/zero-trust-auth/toolkit/pkg/errors"
)

// PKCEStore stores the idp_code_verifier keyed by OAuth state.
// Redis key: idp:pkce:{state}  TTL 10m
type PKCEStore struct {
	client *rdb.Client
}

var _ port.PKCEStore = (*PKCEStore)(nil)

func NewPKCEStore(client *rdb.Client) *PKCEStore {
	return &PKCEStore{client: client}
}

func (s *PKCEStore) Save(ctx context.Context, state, verifier string, ttl time.Duration) error {
	return s.client.Set(ctx, pkceKey(state), verifier, ttl).Err()
}

func (s *PKCEStore) Get(ctx context.Context, state string) (string, error) {
	val, err := s.client.Get(ctx, pkceKey(state)).Result()
	if err != nil {
		if errors.Is(err, rdb.Nil) {
			return "", pkgerrors.ErrNotFound
		}
		return "", err
	}
	return val, nil
}

func (s *PKCEStore) Delete(ctx context.Context, state string) error {
	return s.client.Del(ctx, pkceKey(state)).Err()
}

func pkceKey(state string) string {
	return fmt.Sprintf("idp:pkce:%s", state)
}
