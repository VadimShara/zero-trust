package cases

import (
	"context"

	"github.com/google/uuid"

	"github.com/zero-trust/zero-trust-auth/trust/internal/entities"
)

type Cases struct {
	anonCheck  *AnonymousCheckCase
	evalTrust  *EvaluateTrustCase
	trustCache TrustCache
}

func NewCases(anonCheck *AnonymousCheckCase, evalTrust *EvaluateTrustCase, trustCache TrustCache) *Cases {
	return &Cases{anonCheck: anonCheck, evalTrust: evalTrust, trustCache: trustCache}
}

func (c *Cases) AnonymousCheck(ctx context.Context, ip, userAgent, fingerprint string) (*AnonymousCheckResult, error) {
	return c.anonCheck.Execute(ctx, ip, userAgent, fingerprint)
}

func (c *Cases) Evaluate(ctx context.Context, in EvaluateTrustInput) (*entities.TrustScore, error) {
	return c.evalTrust.Execute(ctx, in)
}

func (c *Cases) IncrFails(ctx context.Context, userID uuid.UUID) (int64, error) {
	return c.trustCache.IncrFails(ctx, userID)
}

func (c *Cases) ResetFails(ctx context.Context, userID uuid.UUID) error {
	return c.trustCache.ResetFails(ctx, userID)
}
