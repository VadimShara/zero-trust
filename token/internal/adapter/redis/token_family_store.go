package redis

import (
	"context"
	"time"

	"github.com/google/uuid"
	rdb "github.com/redis/go-redis/v9"

	"github.com/zero-trust/zero-trust-auth/token/internal/cases"
)

const familyTTL = 7 * 24 * time.Hour // matches refresh token TTL

type TokenFamilyStore struct {
	client *rdb.Client
}

var _ cases.TokenFamilyStore = (*TokenFamilyStore)(nil)

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

// key: family:revoked:{familyID}  TTL = accessTTL (access tokens can't outlive this)
func (s *TokenFamilyStore) MarkRevoked(ctx context.Context, familyID uuid.UUID) error {
	return s.client.Set(ctx, revokedKey(familyID), 1, familyTTL).Err()
}

func (s *TokenFamilyStore) IsRevoked(ctx context.Context, familyID uuid.UUID) (bool, error) {
	err := s.client.Get(ctx, revokedKey(familyID)).Err()
	if err == rdb.Nil {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// key: user:families:{userID}  TTL 7d  — SET of familyIDs issued to this user
func (s *TokenFamilyStore) TrackUserFamily(ctx context.Context, userID, familyID uuid.UUID) error {
	key := "user:families:" + userID.String()
	pipe := s.client.Pipeline()
	pipe.SAdd(ctx, key, familyID.String())
	pipe.Expire(ctx, key, familyTTL)
	_, err := pipe.Exec(ctx)
	return err
}

func (s *TokenFamilyStore) GetUserFamilies(ctx context.Context, userID uuid.UUID) ([]uuid.UUID, error) {
	ids, err := s.client.SMembers(ctx, "user:families:"+userID.String()).Result()
	if err != nil {
		return nil, err
	}
	result := make([]uuid.UUID, 0, len(ids))
	for _, id := range ids {
		if fid, err := uuid.Parse(id); err == nil {
			result = append(result, fid)
		}
	}
	return result, nil
}

func revokedKey(familyID uuid.UUID) string {
	return "family:revoked:" + familyID.String()
}
