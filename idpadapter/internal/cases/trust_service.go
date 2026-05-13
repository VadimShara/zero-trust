package cases

import "context"

type TrustService interface {
	SyncFails(ctx context.Context, userID string, count int64) error
}

type KeycloakAdminService interface {
	GetFailureCount(ctx context.Context, kcUserID string) (int64, error)
}
