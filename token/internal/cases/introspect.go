package cases

import (
	"context"
	"time"

	"github.com/google/uuid"

	pkgerrors "github.com/zero-trust/zero-trust-auth/toolkit/pkg/errors"
)

type IntrospectResult struct {
	Active       bool
	ForcedLogout bool // true when session was terminated due to DENY trust decision
	UserID       uuid.UUID
	Roles        []string
	TrustScore   float64
	Exp          int64
}

type IntrospectCase struct {
	access  AccessTokenStore
	refresh RefreshTokenStore
	family  TokenFamilyStore
	trust   TrustService
	events  EventPublisher
}

func NewIntrospectCase(
	access AccessTokenStore,
	refresh RefreshTokenStore,
	family TokenFamilyStore,
	trust TrustService,
	events EventPublisher,
) *IntrospectCase {
	return &IntrospectCase{access: access, refresh: refresh, family: family, trust: trust, events: events}
}

func (c *IntrospectCase) Execute(ctx context.Context, rawToken string, tc TrustContext) (*IntrospectResult, error) {
	at, err := c.access.Get(ctx, rawToken)
	if err != nil {
		if isNotFound(err) {
			return &IntrospectResult{Active: false}, nil
		}
		return nil, err
	}
	if at.Exp < time.Now().Unix() {
		return &IntrospectResult{Active: false}, nil
	}

	// Reject access tokens whose family was revoked (reuse attack or forced logout).
	if revoked, err := c.family.IsRevoked(ctx, at.FamilyID); err != nil || revoked {
		return &IntrospectResult{Active: false}, nil
	}

	// Re-evaluate trust on every introspect — Zero Trust core mechanism.
	tc.UserID = at.UserID
	newScore, decision, err := c.trust.Evaluate(ctx, tc)
	if err == nil {
		at.TrustScore = newScore
		if remaining := time.Until(time.Unix(at.Exp, 0)); remaining > 0 {
			_ = c.access.Save(ctx, rawToken, at, remaining) // best-effort
		}

		// DENY means a critical trust signal fired (Tor, datacenter IP + many fails, etc.).
		// Force-logout: revoke the entire token family immediately.
		if decision == "DENY" {
			_ = c.access.Delete(ctx, rawToken)
			_ = c.refresh.RevokeFamily(ctx, at.FamilyID)
			_ = c.family.MarkRevoked(ctx, at.FamilyID)
			_ = c.events.Publish(ctx, "token.events", map[string]any{
				"event":       "ForcedLogout",
				"user_id":     at.UserID,
				"family_id":   at.FamilyID,
				"trust_score": newScore,
				"reason":      "trust_score_deny",
				"timestamp":   time.Now().UTC(),
			})
			return &IntrospectResult{Active: false, ForcedLogout: true}, nil
		}
	}

	return &IntrospectResult{
		Active:     true,
		UserID:     at.UserID,
		Roles:      at.Roles,
		TrustScore: at.TrustScore,
		Exp:        at.Exp,
	}, nil
}

func isNotFound(err error) bool {
	return err == pkgerrors.ErrNotFound
}
