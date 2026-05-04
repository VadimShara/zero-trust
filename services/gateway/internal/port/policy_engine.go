package port

import "context"

// PolicyDecision is returned by the policy engine for every authorization check.
type PolicyDecision struct {
	Allow      bool
	DenyReason string // "insufficient_trust" | "insufficient_role" | "" (when allowed)
}

type PolicyEngine interface {
	Decide(ctx context.Context, userID string, roles []string, trustScore float64, resource, action string) (*PolicyDecision, error)
}
