package cases

import (
	"context"

	"github.com/zero-trust/zero-trust-auth/gateway/internal/entities"
)

type RequestCtx struct {
	IP          string
	UserAgent   string
	Fingerprint string
}

type TrustService interface {
	AnonymousCheck(ctx context.Context, rc RequestCtx) (allow bool, err error)
	EvaluateTrust(ctx context.Context, userID string, roles []string, rc RequestCtx, register bool) (score float64, decision string, signals map[string]entities.Signal, err error)
	ResetFails(ctx context.Context, userID string) error
}
