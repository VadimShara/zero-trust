package transport

import (
	"context"

	"github.com/zero-trust/zero-trust-auth/gateway/internal/cases"
	"github.com/zero-trust/zero-trust-auth/gateway/internal/entities"
)

type authFlow interface {
	Authorize(ctx context.Context, clientID, codeChallenge, method, state string, rc cases.RequestCtx) (string, error)
	Continue(ctx context.Context, in cases.ContinueInput) error
	Callback(ctx context.Context, gatewayPublicURL, state string) (*cases.CallbackResult, error)
	SetupMFA(ctx context.Context, state string) (*cases.MFASetupResult, error)
	VerifyMFA(ctx context.Context, state, code string) error
	ExchangeCode(ctx context.Context, code, codeVerifier, clientSecret string) (*cases.TokenResponse, error)
	RefreshToken(ctx context.Context, refreshToken string, rc cases.RequestCtx) (*cases.TokenResponse, error)
	Logout(ctx context.Context, token string, revokeAll bool) error
}

type tokenGuard interface {
	Introspect(ctx context.Context, token string, rc cases.RequestCtx) (active bool, userID string, roles []string, trustScore float64, signals map[string]entities.Signal, err error)
	AdminRevokeUser(ctx context.Context, userID, adminID, reason string) (int, error)
	Decide(ctx context.Context, userID string, roles []string, trustScore float64, resource, action string) (*cases.PolicyDecision, error)
	QueryAudit(ctx context.Context, params map[string]string) (*cases.AuditQueryResult, error)
}
