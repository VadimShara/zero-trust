package cases

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/zero-trust/zero-trust-auth/token/internal/entities"
)

type IssueCase struct {
	access     AccessTokenStore
	refresh    RefreshTokenStore
	family     TokenFamilyStore
	accessTTL  time.Duration
	refreshTTL time.Duration
}

func NewIssueCase(access AccessTokenStore, refresh RefreshTokenStore, family TokenFamilyStore, accessTTL, refreshTTL time.Duration) *IssueCase {
	return &IssueCase{access: access, refresh: refresh, family: family, accessTTL: accessTTL, refreshTTL: refreshTTL}
}

func (c *IssueCase) Execute(ctx context.Context, userID uuid.UUID, roles []string, trustScore float64, loginSignals map[string]entities.Signal) (atRaw, rtRaw string, err error) {
	familyID := uuid.New()
	return mintPair(ctx, userID, roles, trustScore, loginSignals, familyID, c.access, c.refresh, c.family, c.accessTTL, c.refreshTTL)
}

func mintPair(
	ctx context.Context,
	userID uuid.UUID,
	roles []string,
	trustScore float64,
	loginSignals map[string]entities.Signal,
	familyID uuid.UUID,
	access AccessTokenStore,
	refresh RefreshTokenStore,
	family TokenFamilyStore,
	accessTTL time.Duration,
	refreshTTL time.Duration,
) (atRaw, rtRaw string, err error) {
	at := entities.NewAccessToken(userID, roles, trustScore, loginSignals, familyID, accessTTL)
	rt := entities.NewRefreshToken(userID, roles, familyID, at.Hash, refreshTTL)

	if err = access.Save(ctx, at.Raw, at, accessTTL); err != nil {
		return "", "", err
	}
	if err = refresh.Save(ctx, rt.Raw, rt, refreshTTL); err != nil {
		return "", "", err
	}
	if err = family.AddToken(ctx, familyID, rt.Hash); err != nil {
		return "", "", err
	}
	_ = family.TrackUserFamily(ctx, userID, familyID)
	return at.Raw, rt.Raw, nil
}
