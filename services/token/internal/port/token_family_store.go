package port

import (
	"context"

	"github.com/google/uuid"
)

type TokenFamilyStore interface {
	AddToken(ctx context.Context, familyID uuid.UUID, tokenHash string) error
	GetFamily(ctx context.Context, familyID uuid.UUID) ([]string, error)
}
