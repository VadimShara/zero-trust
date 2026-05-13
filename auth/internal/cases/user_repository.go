package cases

import (
	"context"

	"github.com/zero-trust/zero-trust-auth/auth/internal/entities"
)

type UserRepository interface {
	FindByIDPSub(ctx context.Context, idp, sub string) (*entities.User, error)
	CreateUser(ctx context.Context, u *entities.User) error
	CreateIDPLink(ctx context.Context, link *entities.UserIDPLink) error
	GetTOTPSecret(ctx context.Context, userID string) (string, error)
	SetTOTPSecret(ctx context.Context, userID, secret string) error
	IsTOTPEnrolled(ctx context.Context, userID string) (bool, error)
	SetTOTPEnrolled(ctx context.Context, userID string) error
}
