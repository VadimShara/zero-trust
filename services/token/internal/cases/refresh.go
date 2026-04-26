package cases

import (
	"context"
	"time"

	"github.com/zero-trust/zero-trust-auth/services/token/internal/entities"
	"github.com/zero-trust/zero-trust-auth/services/token/internal/port"
	pkgerrors "github.com/zero-trust/zero-trust-auth/toolkit/pkg/errors"
)

type RefreshCase struct {
	access  port.AccessTokenStore
	refresh port.RefreshTokenStore
	family  port.TokenFamilyStore
	events  port.EventPublisher
	trust   port.TrustService
}

func NewRefreshCase(
	access port.AccessTokenStore,
	refresh port.RefreshTokenStore,
	family port.TokenFamilyStore,
	events port.EventPublisher,
	trust port.TrustService,
) *RefreshCase {
	return &RefreshCase{access: access, refresh: refresh, family: family, events: events, trust: trust}
}

func (c *RefreshCase) Execute(ctx context.Context, rawRefresh string, tc port.TrustContext) (atRaw, rtRaw string, err error) {
	rt, err := c.refresh.Get(ctx, rawRefresh)
	if err != nil {
		if isNotFound(err) {
			return "", "", pkgerrors.ErrTokenExpired
		}
		return "", "", err
	}

	switch rt.Status {
	case entities.Consumed:
		// Token reuse attack — revoke the entire family immediately.
		_ = c.refresh.RevokeFamily(ctx, rt.FamilyID)
		_ = c.events.Publish(ctx, "token.events", map[string]any{
			"event":     "TokenReuseAttackDetected",
			"user_id":   rt.UserID,
			"family_id": rt.FamilyID,
			"timestamp": time.Now().UTC(),
		})
		return "", "", pkgerrors.ErrTokenReuse

	case entities.Revoked:
		return "", "", pkgerrors.ErrTokenExpired
	}

	// Mark old token consumed before issuing new ones.
	if err = c.refresh.MarkConsumed(ctx, rawRefresh); err != nil {
		return "", "", err
	}

	// Re-evaluate trust with current request context.
	tc.UserID = rt.UserID
	trustScore := 0.0
	if score, err := c.trust.Evaluate(ctx, tc); err == nil {
		trustScore = score
	}

	return mintPair(ctx, rt.UserID, rt.Roles, trustScore, rt.FamilyID, c.access, c.refresh, c.family)
}
