package cases

import (
	"context"
	"crypto/sha256"
	"encoding/base64"

	"github.com/zero-trust/zero-trust-auth/services/gateway/internal/port"
	pkgerrors "github.com/zero-trust/zero-trust-auth/toolkit/pkg/errors"
)

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

type ExchangeCodeCase struct {
	authcodes    port.AuthCodeStore
	tokens       port.TokenService
	clientSecret string
}

func NewExchangeCodeCase(authcodes port.AuthCodeStore, tokens port.TokenService, clientSecret string) *ExchangeCodeCase {
	return &ExchangeCodeCase{authcodes: authcodes, tokens: tokens, clientSecret: clientSecret}
}

func (c *ExchangeCodeCase) Execute(ctx context.Context, code, codeVerifier, clientSecret string) (*TokenResponse, error) {
	// Atomic get+delete — code becomes invalid after this call.
	authCode, err := c.authcodes.GetAndDelete(ctx, code)
	if err != nil {
		return nil, pkgerrors.ErrNotFound
	}

	// Verify client secret.
	if clientSecret != c.clientSecret {
		return nil, pkgerrors.ErrUnauthorized
	}

	// Verify PKCE: BASE64URL(SHA256(code_verifier)) must equal stored code_challenge.
	h := sha256.Sum256([]byte(codeVerifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	if computed != authCode.CodeChallenge {
		return nil, pkgerrors.ErrInvalidPKCE
	}

	accessToken, refreshToken, err := c.tokens.Issue(ctx, authCode.UserID, authCode.Roles, authCode.TrustScore)
	if err != nil {
		return nil, err
	}

	return &TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    900, // 15 minutes in seconds
	}, nil
}
