package port

import (
	"context"

	"github.com/zero-trust/zero-trust-auth/services/auth/internal/entities"
)

type UserRepository interface {
	FindByIDPSub(ctx context.Context, idp, sub string) (*entities.User, error)
	CreateUser(ctx context.Context, u *entities.User) error
	CreateIDPLink(ctx context.Context, link *entities.UserIDPLink) error
}
