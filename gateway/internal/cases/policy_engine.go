package cases

import "context"

type PolicyDecision struct {
	Allow      bool
	DenyReason string // "insufficient_trust" | "insufficient_role" | ""
}

type PolicyEngine interface {
	Decide(ctx context.Context, userID string, roles []string, trustScore float64, resource, action string) (*PolicyDecision, error)
}
