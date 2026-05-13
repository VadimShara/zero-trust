package transport

import (
	"context"

	"github.com/zero-trust/zero-trust-auth/idpadapter/internal/cases"
)

type UseCases interface {
	GetLoginURL(ctx context.Context, state string) (string, error)
	HandleCallback(ctx context.Context, code, state string, rc cases.RequestCtx) (string, error)
	GetLogoutURL(postLogoutRedirectURI string) string
}
