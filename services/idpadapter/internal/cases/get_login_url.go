package cases

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"time"

	"github.com/zero-trust/zero-trust-auth/services/idpadapter/internal/port"
)

const pkceTTL = 10 * time.Minute // matches session:{state} TTL on Gateway side

type GetLoginURLCase struct {
	pkce port.PKCEStore
	oidc port.OIDCProvider
}

func NewGetLoginURLCase(pkce port.PKCEStore, oidc port.OIDCProvider) *GetLoginURLCase {
	return &GetLoginURLCase{pkce: pkce, oidc: oidc}
}

// Execute generates an independent PKCE pair for the IDPAdapter ↔ Keycloak
// flow (ADR-003), stores the verifier in Redis, and returns the Keycloak
// authorization URL. This PKCE pair is completely separate from the client's
// code_verifier used in the Client ↔ Gateway flow.
func (c *GetLoginURLCase) Execute(ctx context.Context, state string) (string, error) {
	// verifier: 32 random bytes → base64url, no padding (RFC 7636 §4.1)
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	verifier := base64.RawURLEncoding.EncodeToString(b)

	// challenge: BASE64URL(SHA256(ASCII(verifier))) (RFC 7636 §4.2)
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	if err := c.pkce.Save(ctx, state, verifier, pkceTTL); err != nil {
		return "", err
	}

	return c.oidc.AuthorizeURL(state, challenge), nil
}
