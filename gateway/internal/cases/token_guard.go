package cases

import "context"

type TokenGuard struct {
	tokens TokenService
	policy PolicyEngine
	audit  AuditService
}

func NewTokenGuard(tokens TokenService, policy PolicyEngine, audit AuditService) *TokenGuard {
	return &TokenGuard{tokens: tokens, policy: policy, audit: audit}
}

func (g *TokenGuard) Introspect(ctx context.Context, token string, rc RequestCtx) (bool, string, []string, float64, error) {
	return g.tokens.Introspect(ctx, token, rc)
}

func (g *TokenGuard) AdminRevokeUser(ctx context.Context, userID, adminID, reason string) (int, error) {
	return g.tokens.AdminRevokeUser(ctx, userID, adminID, reason)
}

func (g *TokenGuard) Decide(ctx context.Context, userID string, roles []string, trustScore float64, resource, action string) (*PolicyDecision, error) {
	return g.policy.Decide(ctx, userID, roles, trustScore, resource, action)
}

func (g *TokenGuard) QueryAudit(ctx context.Context, params map[string]string) (*AuditQueryResult, error) {
	return g.audit.QueryEvents(ctx, params)
}
