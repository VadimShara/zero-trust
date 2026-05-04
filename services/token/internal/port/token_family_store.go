package port

import (
	"context"

	"github.com/google/uuid"
)

type TokenFamilyStore interface {
	AddToken(ctx context.Context, familyID uuid.UUID, tokenHash string) error
	GetFamily(ctx context.Context, familyID uuid.UUID) ([]string, error)
	MarkRevoked(ctx context.Context, familyID uuid.UUID) error
	IsRevoked(ctx context.Context, familyID uuid.UUID) (bool, error)
	// TrackUserFamily registers familyID under the user so RevokeAllForUser can find it.
	TrackUserFamily(ctx context.Context, userID, familyID uuid.UUID) error
	// GetUserFamilies returns all family IDs ever issued to the user.
	GetUserFamilies(ctx context.Context, userID uuid.UUID) ([]uuid.UUID, error)
}
