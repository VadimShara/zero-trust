package cases

import (
	"context"
	"time"

	"github.com/zero-trust/zero-trust-auth/gateway/internal/entities"
)

type AuthCodeStore interface {
	Save(ctx context.Context, a *entities.AuthCode, ttl time.Duration) error
	// GetAndDelete is atomic: get + del in one round trip.
	// Returns ErrNotFound if the code does not exist or has already been consumed.
	GetAndDelete(ctx context.Context, code string) (*entities.AuthCode, error)
	SaveByState(ctx context.Context, state, code string, ttl time.Duration) error
	GetByState(ctx context.Context, state string) (string, error)
}
