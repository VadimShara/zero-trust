package cases

import (
	"context"

	"github.com/google/uuid"

	"github.com/zero-trust/zero-trust-auth/token/internal/entities"
)

type Cases struct {
	issue       *IssueCase
	introspect  *IntrospectCase
	refresh     *RefreshCase
	revoke      *RevokeCase
	adminRevoke *AdminRevokeCase
}

func NewCases(
	issue *IssueCase,
	introspect *IntrospectCase,
	refresh *RefreshCase,
	revoke *RevokeCase,
	adminRevoke *AdminRevokeCase,
) *Cases {
	return &Cases{
		issue:       issue,
		introspect:  introspect,
		refresh:     refresh,
		revoke:      revoke,
		adminRevoke: adminRevoke,
	}
}

func (c *Cases) IssueTokens(ctx context.Context, userID uuid.UUID, roles []string, trustScore float64, loginSignals map[string]entities.Signal) (atRaw, rtRaw string, err error) {
	return c.issue.Execute(ctx, userID, roles, trustScore, loginSignals)
}

func (c *Cases) Introspect(ctx context.Context, rawToken string, tc TrustContext) (*IntrospectResult, error) {
	return c.introspect.Execute(ctx, rawToken, tc)
}

func (c *Cases) Refresh(ctx context.Context, rawRefresh string, tc TrustContext) (atRaw, rtRaw string, err error) {
	return c.refresh.Execute(ctx, rawRefresh, tc)
}

func (c *Cases) Revoke(ctx context.Context, rawToken string, revokeFamily bool) error {
	return c.revoke.Execute(ctx, rawToken, revokeFamily)
}

func (c *Cases) AdminRevokeUser(ctx context.Context, userID uuid.UUID, adminID, reason string) (int, error) {
	return c.adminRevoke.RevokeUser(ctx, userID, adminID, reason)
}
