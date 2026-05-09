package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	rdb "github.com/redis/go-redis/v9"

	"github.com/zero-trust/zero-trust-auth/gateway/internal/entities"
	"github.com/zero-trust/zero-trust-auth/gateway/internal/cases"
	pkgerrors "github.com/zero-trust/zero-trust-auth/toolkit/pkg/errors"
)

// AuthCodeStore persists one-time authorization codes and their state→code mapping.
// Redis keys:
//
//	authcode:{code}        TTL 60s  → AuthCode JSON
//	authcode:state:{state} TTL 60s  → own_code string
type AuthCodeStore struct {
	client *rdb.Client
}

var _ cases.AuthCodeStore = (*AuthCodeStore)(nil)

func NewAuthCodeStore(client *rdb.Client) *AuthCodeStore {
	return &AuthCodeStore{client: client}
}

func (s *AuthCodeStore) Save(ctx context.Context, a *entities.AuthCode, ttl time.Duration) error {
	data, err := json.Marshal(a)
	if err != nil {
		return err
	}
	return s.client.Set(ctx, authcodeKey(a.Code), data, ttl).Err()
}

// GetAndDelete is atomic: Lua script reads and deletes the key in one round trip,
// ensuring the code can only be used once even under concurrent requests.
var getAndDelScript = rdb.NewScript(`
local v = redis.call('GET', KEYS[1])
if v ~= false then
    redis.call('DEL', KEYS[1])
end
return v
`)

func (s *AuthCodeStore) GetAndDelete(ctx context.Context, code string) (*entities.AuthCode, error) {
	val, err := getAndDelScript.Run(ctx, s.client, []string{authcodeKey(code)}).Text()
	if err != nil {
		if errors.Is(err, rdb.Nil) {
			return nil, pkgerrors.ErrNotFound
		}
		return nil, err
	}
	var a entities.AuthCode
	if err := json.Unmarshal([]byte(val), &a); err != nil {
		return nil, err
	}
	return &a, nil
}

func (s *AuthCodeStore) SaveByState(ctx context.Context, state, code string, ttl time.Duration) error {
	return s.client.Set(ctx, stateCodeKey(state), code, ttl).Err()
}

func (s *AuthCodeStore) GetByState(ctx context.Context, state string) (string, error) {
	val, err := s.client.Get(ctx, stateCodeKey(state)).Result()
	if err != nil {
		if errors.Is(err, rdb.Nil) {
			return "", pkgerrors.ErrNotFound
		}
		return "", err
	}
	return val, nil
}

func authcodeKey(code string) string  { return fmt.Sprintf("authcode:%s", code) }
func stateCodeKey(state string) string { return fmt.Sprintf("authcode:state:%s", state) }
