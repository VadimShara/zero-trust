package port

import (
	"context"
	"time"

	"github.com/zero-trust/zero-trust-auth/services/token/internal/entities"
)

type AccessTokenStore interface {
	Save(ctx context.Context, raw string, t *entities.AccessToken, ttl time.Duration) error
	Get(ctx context.Context, raw string) (*entities.AccessToken, error)
	Delete(ctx context.Context, raw string) error
}
