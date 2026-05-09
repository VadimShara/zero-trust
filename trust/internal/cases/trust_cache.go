package cases

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/zero-trust/zero-trust-auth/trust/internal/entities"
)

type TrustCache interface {
	GetLastContext(ctx context.Context, userID uuid.UUID) (*entities.TrustContext, error)
	SetLastContext(ctx context.Context, userID uuid.UUID, tc *entities.TrustContext, ttl time.Duration) error
	GetDeviceSet(ctx context.Context, userID uuid.UUID) ([]string, error)
	AddDevice(ctx context.Context, userID uuid.UUID, hash string) error
	GetFails(ctx context.Context, userID uuid.UUID) (int64, error)
	IncrFails(ctx context.Context, userID uuid.UUID) (int64, error)
	ResetFails(ctx context.Context, userID uuid.UUID) error
	IncrIPFails(ctx context.Context, ipHash string) (int64, error)
}
