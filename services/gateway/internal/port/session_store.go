package port

import (
	"context"
	"time"

	"github.com/zero-trust/zero-trust-auth/services/gateway/internal/entities"
)

type SessionStore interface {
	Save(ctx context.Context, s *entities.OAuthSession, ttl time.Duration) error
	Get(ctx context.Context, state string) (*entities.OAuthSession, error)
	Delete(ctx context.Context, state string) error
}
