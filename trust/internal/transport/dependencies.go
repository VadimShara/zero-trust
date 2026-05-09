package transport

import (
	"context"

	"github.com/google/uuid"

	"github.com/zero-trust/zero-trust-auth/trust/internal/cases"
	"github.com/zero-trust/zero-trust-auth/trust/internal/entities"
)

type UseCases interface {
	AnonymousCheck(ctx context.Context, ip, userAgent, fingerprint string) (*cases.AnonymousCheckResult, error)
	Evaluate(ctx context.Context, in cases.EvaluateTrustInput) (*entities.TrustScore, error)
	IncrFails(ctx context.Context, userID uuid.UUID) (int64, error)
	ResetFails(ctx context.Context, userID uuid.UUID) error
}
