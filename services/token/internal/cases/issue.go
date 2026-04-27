package cases

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/zero-trust/zero-trust-auth/services/token/internal/entities"
	"github.com/zero-trust/zero-trust-auth/services/token/internal/port"
)

const (
	accessTTL  = 1 * time.Hour // 15m in production; extended for manual testing
	refreshTTL = 7 * 24 * time.Hour
)

type IssueCase struct {
	access  port.AccessTokenStore
	refresh port.RefreshTokenStore
	family  port.TokenFamilyStore
}

func NewIssueCase(access port.AccessTokenStore, refresh port.RefreshTokenStore, family port.TokenFamilyStore) *IssueCase {
	return &IssueCase{access: access, refresh: refresh, family: family}
}

func (c *IssueCase) Execute(ctx context.Context, userID uuid.UUID, roles []string, trustScore float64) (atRaw, rtRaw string, err error) {
	familyID := uuid.New()
	return mintPair(ctx, userID, roles, trustScore, familyID, c.access, c.refresh, c.family)
}

// mintPair is shared with RefreshCase for token rotation.
func mintPair(
	ctx context.Context,
	userID uuid.UUID,
	roles []string,
	trustScore float64,
	familyID uuid.UUID,
	access port.AccessTokenStore,
	refresh port.RefreshTokenStore,
	family port.TokenFamilyStore,
) (atRaw, rtRaw string, err error) {
	at := entities.NewAccessToken(userID, roles, trustScore, familyID, accessTTL)
	rt := entities.NewRefreshToken(userID, roles, familyID, refreshTTL)

	if err = access.Save(ctx, at.Raw, at, accessTTL); err != nil {
		return "", "", err
	}
	if err = refresh.Save(ctx, rt.Raw, rt, refreshTTL); err != nil {
		return "", "", err
	}
	// Only refresh token hashes live in the family set — used by RevokeFamily.
	if err = family.AddToken(ctx, familyID, rt.Hash); err != nil {
		return "", "", err
	}
	return at.Raw, rt.Raw, nil
}
