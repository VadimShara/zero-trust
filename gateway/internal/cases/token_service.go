package cases

import (
	"context"

	"github.com/zero-trust/zero-trust-auth/gateway/internal/entities"
)

type TokenService interface {
	Issue(ctx context.Context, userID string, roles []string, trustScore float64, loginSignals map[string]entities.Signal) (accessToken, refreshToken string, err error)
	Introspect(ctx context.Context, token string, rc RequestCtx) (active bool, userID string, roles []string, trustScore float64, signals map[string]entities.Signal, err error)
	Refresh(ctx context.Context, refreshToken string, rc RequestCtx) (accessToken, newRefreshToken string, err error)
	Revoke(ctx context.Context, token string, revokeAll bool) error
	AdminRevokeUser(ctx context.Context, userID, adminID, reason string) (int, error)
}
