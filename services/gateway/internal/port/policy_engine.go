package port

import "context"

type PolicyEngine interface {
	Allow(ctx context.Context, userID string, roles []string, trustScore float64, resource, action string) (bool, error)
}
