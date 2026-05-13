package cases

import "context"

type IDPAdapterService interface {
	GetLoginURL(ctx context.Context, state string) (string, error)
	GetLogoutURL(ctx context.Context, postLogoutRedirectURI string) (string, error)
}
