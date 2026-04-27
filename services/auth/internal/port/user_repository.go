package port

import (
	"context"

	"github.com/zero-trust/zero-trust-auth/services/auth/internal/entities"
)

type UserRepository interface {
	FindByIDPSub(ctx context.Context, idp, sub string) (*entities.User, error)
	CreateUser(ctx context.Context, u *entities.User) error
	CreateIDPLink(ctx context.Context, link *entities.UserIDPLink) error
	GetTOTPSecret(ctx context.Context, userID string) (string, error)  // ErrNotFound if not set
	SetTOTPSecret(ctx context.Context, userID, secret string) error
}
