package cases

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/zero-trust/zero-trust-auth/token/internal/entities"
)

type RefreshTokenStore interface {
	Save(ctx context.Context, raw string, t *entities.RefreshToken, ttl time.Duration) error
	Get(ctx context.Context, raw string) (*entities.RefreshToken, error)
	MarkConsumed(ctx context.Context, raw string) error
	RevokeFamily(ctx context.Context, familyID uuid.UUID) error
}
