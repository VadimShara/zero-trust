package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	rdb "github.com/redis/go-redis/v9"

	"github.com/zero-trust/zero-trust-auth/token/internal/entities"
	"github.com/zero-trust/zero-trust-auth/token/internal/cases"
	pkgerrors "github.com/zero-trust/zero-trust-auth/toolkit/pkg/errors"
)

type RefreshTokenStore struct {
	client *rdb.Client
}

var _ cases.RefreshTokenStore = (*RefreshTokenStore)(nil)

func NewRefreshTokenStore(client *rdb.Client) *RefreshTokenStore {
	return &RefreshTokenStore{client: client}
}

// key: token:refresh:{sha256(raw)}  TTL 7d
func (s *RefreshTokenStore) Save(ctx context.Context, raw string, t *entities.RefreshToken, ttl time.Duration) error {
	data, err := json.Marshal(t)
	if err != nil {
		return err
	}
	return s.client.Set(ctx, refreshKey(raw), data, ttl).Err()
}

func (s *RefreshTokenStore) Get(ctx context.Context, raw string) (*entities.RefreshToken, error) {
	val, err := s.client.Get(ctx, refreshKey(raw)).Result()
	if err != nil {
		if errors.Is(err, rdb.Nil) {
			return nil, pkgerrors.ErrNotFound
		}
		return nil, err
	}
	var t entities.RefreshToken
	if err := json.Unmarshal([]byte(val), &t); err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *RefreshTokenStore) MarkConsumed(ctx context.Context, raw string) error {
	return s.setStatus(ctx, refreshKey(raw), entities.Consumed)
}

// RevokeFamily marks every refresh token in the family as Revoked.
// family:{familyID} holds the set of refresh token hashes (sha256 of raw).
func (s *RefreshTokenStore) RevokeFamily(ctx context.Context, familyID uuid.UUID) error {
	hashes, err := s.client.SMembers(ctx, familyKey(familyID)).Result()
	if err != nil {
		return err
	}
	for _, hash := range hashes {
		key := fmt.Sprintf("token:refresh:%s", hash)
		_ = s.setStatus(ctx, key, entities.Revoked) // best-effort per token
	}
	return nil
}

// setStatus reads the stored token, updates its Status, and writes it back
// keeping the original TTL intact (rdb.KeepTTL = -1).
func (s *RefreshTokenStore) setStatus(ctx context.Context, key string, status entities.Status) error {
	val, err := s.client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, rdb.Nil) {
			return nil // already gone — treat as success
		}
		return err
	}
	var t entities.RefreshToken
	if err := json.Unmarshal([]byte(val), &t); err != nil {
		return err
	}
	t.Status = status
	data, err := json.Marshal(t)
	if err != nil {
		return err
	}
	return s.client.Set(ctx, key, data, rdb.KeepTTL).Err()
}

func refreshKey(raw string) string {
	return fmt.Sprintf("token:refresh:%s", hashRaw(raw))
}

func familyKey(familyID uuid.UUID) string {
	return fmt.Sprintf("family:%s", familyID)
}
