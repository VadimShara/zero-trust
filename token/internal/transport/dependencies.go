package transport

import (
	"context"

	"github.com/google/uuid"

	"github.com/zero-trust/zero-trust-auth/token/internal/cases"
	"github.com/zero-trust/zero-trust-auth/token/internal/entities"
)

type UseCases interface {
	IssueTokens(ctx context.Context, userID uuid.UUID, roles []string, trustScore float64, loginSignals map[string]entities.Signal) (atRaw, rtRaw string, err error)
	Introspect(ctx context.Context, rawToken string, tc cases.TrustContext) (*cases.IntrospectResult, error)
	Refresh(ctx context.Context, rawRefresh string, tc cases.TrustContext) (atRaw, rtRaw string, err error)
	Revoke(ctx context.Context, rawToken string, revokeFamily bool) error
	AdminRevokeUser(ctx context.Context, userID uuid.UUID, adminID, reason string) (int, error)
}
