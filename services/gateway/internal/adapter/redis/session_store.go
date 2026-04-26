package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	rdb "github.com/redis/go-redis/v9"

	"github.com/zero-trust/zero-trust-auth/services/gateway/internal/entities"
	"github.com/zero-trust/zero-trust-auth/services/gateway/internal/port"
	pkgerrors "github.com/zero-trust/zero-trust-auth/toolkit/pkg/errors"
)

// SessionStore persists OAuth sessions keyed by state.
// Redis key: session:{state}  TTL 10m
type SessionStore struct {
	client *rdb.Client
}

var _ port.SessionStore = (*SessionStore)(nil)

func NewSessionStore(client *rdb.Client) *SessionStore {
	return &SessionStore{client: client}
}

func (s *SessionStore) Save(ctx context.Context, sess *entities.OAuthSession, ttl time.Duration) error {
	data, err := json.Marshal(sess)
	if err != nil {
		return err
	}
	return s.client.Set(ctx, sessionKey(sess.State), data, ttl).Err()
}

func (s *SessionStore) Get(ctx context.Context, state string) (*entities.OAuthSession, error) {
	val, err := s.client.Get(ctx, sessionKey(state)).Result()
	if err != nil {
		if errors.Is(err, rdb.Nil) {
			return nil, pkgerrors.ErrNotFound
		}
		return nil, err
	}
	var sess entities.OAuthSession
	if err := json.Unmarshal([]byte(val), &sess); err != nil {
		return nil, err
	}
	return &sess, nil
}

func (s *SessionStore) Delete(ctx context.Context, state string) error {
	return s.client.Del(ctx, sessionKey(state)).Err()
}

func sessionKey(state string) string {
	return fmt.Sprintf("session:%s", state)
}
