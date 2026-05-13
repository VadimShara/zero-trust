package cases

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"time"
)

const pkceTTL = 10 * time.Minute

type GetLoginURLCase struct {
	pkce PKCEStore
	oidc OIDCProvider
}

func NewGetLoginURLCase(pkce PKCEStore, oidc OIDCProvider) *GetLoginURLCase {
	return &GetLoginURLCase{pkce: pkce, oidc: oidc}
}

func (c *GetLoginURLCase) Execute(ctx context.Context, state string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	verifier := base64.RawURLEncoding.EncodeToString(b)

	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	if err := c.pkce.Save(ctx, state, verifier, pkceTTL); err != nil {
		return "", err
	}

	return c.oidc.AuthorizeURL(state, challenge), nil
}
