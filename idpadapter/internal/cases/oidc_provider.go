package cases

import (
	"context"

	"github.com/zero-trust/zero-trust-auth/idpadapter/internal/entities"
)

type OIDCProvider interface {
	AuthorizeURL(state, challenge string) string
	Exchange(ctx context.Context, code, verifier string) (*entities.IDPIdentity, error)
}
