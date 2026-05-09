package cases

import "context"

type AuthService interface {
	ResolveUser(ctx context.Context, sub, email, idp string) (userID string, err error)
}
