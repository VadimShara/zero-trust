package port

import "context"

type TokenService interface {
	Issue(ctx context.Context, userID string, roles []string, trustScore float64) (accessToken, refreshToken string, err error)
	Introspect(ctx context.Context, token string) (active bool, userID string, roles []string, trustScore float64, err error)
	Refresh(ctx context.Context, refreshToken string, rc RequestCtx) (accessToken, newRefreshToken string, err error)
	Revoke(ctx context.Context, token string, revokeAll bool) error
}
