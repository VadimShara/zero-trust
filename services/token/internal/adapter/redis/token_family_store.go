package redis

import (
	"context"
	"time"

	"github.com/google/uuid"
	rdb "github.com/redis/go-redis/v9"

	"github.com/zero-trust/zero-trust-auth/services/token/internal/port"
)

const familyTTL = 7 * 24 * time.Hour // matches refresh token TTL

type TokenFamilyStore struct {
	client *rdb.Client
}

var _ port.TokenFamilyStore = (*TokenFamilyStore)(nil)

func NewTokenFamilyStore(client *rdb.Client) *TokenFamilyStore {
	return &TokenFamilyStore{client: client}
}

// key: family:{familyID}  TTL 7d  — Redis SET of refresh token hashes
func (s *TokenFamilyStore) AddToken(ctx context.Context, familyID uuid.UUID, tokenHash string) error {
	key := familyKey(familyID)
	pipe := s.client.Pipeline()
	pipe.SAdd(ctx, key, tokenHash)
	pipe.Expire(ctx, key, familyTTL)
	_, err := pipe.Exec(ctx)
	return err
}

func (s *TokenFamilyStore) GetFamily(ctx context.Context, familyID uuid.UUID) ([]string, error) {
	return s.client.SMembers(ctx, familyKey(familyID)).Result()
}
