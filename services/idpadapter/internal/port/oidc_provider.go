package port

import (
	"context"

	"github.com/zero-trust/zero-trust-auth/services/idpadapter/internal/entities"
)

type OIDCProvider interface {
	// AuthorizeURL builds the IDP authorization redirect URL with S256 PKCE.
	AuthorizeURL(state, challenge string) string
	// Exchange exchanges the authorization code for an IDPIdentity, verifying
	// the id_token signature via JWKS.
	Exchange(ctx context.Context, code, verifier string) (*entities.IDPIdentity, error)
}
