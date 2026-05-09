package cases

import (
	"context"

	"github.com/google/uuid"
)

type TrustContext struct {
	UserID      uuid.UUID
	IP          string
	UserAgent   string
	Fingerprint string
}

type TrustService interface {
	Evaluate(ctx context.Context, tc TrustContext) (trustScore float64, decision string, err error)
}
