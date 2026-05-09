package cases

import (
	"context"
	"time"

	"github.com/zero-trust/zero-trust-auth/token/internal/entities"
	pkgerrors "github.com/zero-trust/zero-trust-auth/toolkit/pkg/errors"
)

type RefreshCase struct {
	access  AccessTokenStore
	refresh RefreshTokenStore
	family  TokenFamilyStore
	events  EventPublisher
	trust   TrustService
}

func NewRefreshCase(
	access AccessTokenStore,
	refresh RefreshTokenStore,
	family TokenFamilyStore,
	events EventPublisher,
	trust TrustService,
) *RefreshCase {
	return &RefreshCase{access: access, refresh: refresh, family: family, events: events, trust: trust}
}

func (c *RefreshCase) Execute(ctx context.Context, rawRefresh string, tc TrustContext) (atRaw, rtRaw string, err error) {
	rt, err := c.refresh.Get(ctx, rawRefresh)
	if err != nil {
		if isNotFound(err) {
			return "", "", pkgerrors.ErrTokenExpired
		}
		return "", "", err
	}

	switch rt.Status {
	case entities.Consumed:
		// Token reuse attack — revoke all refresh tokens in the family and
		// mark the family as revoked so access tokens are rejected on introspect.
		_ = c.refresh.RevokeFamily(ctx, rt.FamilyID)
		_ = c.family.MarkRevoked(ctx, rt.FamilyID)
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

	// Mark old RT consumed and delete its paired AT — it must not outlive the rotation.
	if err = c.refresh.MarkConsumed(ctx, rawRefresh); err != nil {
		return "", "", err
	}
	_ = c.access.DeleteByHash(ctx, rt.ATHash) // best-effort: AT may have already expired

	// Re-evaluate trust with current request context.
	tc.UserID = rt.UserID
	trustScore := 0.0
	if score, _, err := c.trust.Evaluate(ctx, tc); err == nil {
		trustScore = score
	}

	return mintPair(ctx, rt.UserID, rt.Roles, trustScore, rt.FamilyID, c.access, c.refresh, c.family)
}
