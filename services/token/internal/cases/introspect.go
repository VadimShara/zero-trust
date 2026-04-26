package cases

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/zero-trust/zero-trust-auth/services/token/internal/port"
	pkgerrors "github.com/zero-trust/zero-trust-auth/toolkit/pkg/errors"
)

type IntrospectResult struct {
	Active     bool
	UserID     uuid.UUID
	Roles      []string
	TrustScore float64
	Exp        int64
}

type IntrospectCase struct {
	access port.AccessTokenStore
	trust  port.TrustService
}

func NewIntrospectCase(access port.AccessTokenStore, trust port.TrustService) *IntrospectCase {
	return &IntrospectCase{access: access, trust: trust}
}

func (c *IntrospectCase) Execute(ctx context.Context, rawToken string, tc port.TrustContext) (*IntrospectResult, error) {
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

	// Re-evaluate trust on every introspect — Zero Trust core mechanism.
	tc.UserID = at.UserID
	if newScore, err := c.trust.Evaluate(ctx, tc); err == nil {
		at.TrustScore = newScore
		// Overwrite in Redis keeping the original expiry (compute remaining TTL).
		if remaining := time.Until(time.Unix(at.Exp, 0)); remaining > 0 {
			_ = c.access.Save(ctx, rawToken, at, remaining) // best-effort
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
