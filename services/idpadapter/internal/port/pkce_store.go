package port

import (
	"context"
	"time"
)

type PKCEStore interface {
	Save(ctx context.Context, state, verifier string, ttl time.Duration) error
	Get(ctx context.Context, state string) (string, error)
	Delete(ctx context.Context, state string) error
}
