package transport

import (
	"context"

	"github.com/google/uuid"

	"github.com/zero-trust/zero-trust-auth/auth/internal/cases"
)

type UseCases interface {
	ResolveUser(ctx context.Context, idp, sub, email string) (uuid.UUID, bool, error)
	SetupMFA(ctx context.Context, userID, email string) (*cases.SetupResult, error)
	VerifyMFA(ctx context.Context, userID, code string) (bool, error)
}
