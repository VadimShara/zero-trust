package cases

import (
	"context"
	"crypto/sha256"
	"encoding/base64"

	pkgerrors "github.com/zero-trust/zero-trust-auth/toolkit/pkg/errors"
)

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

type ExchangeCodeCase struct {
	authcodes    AuthCodeStore
	tokens       TokenService
	clientSecret string
}

func NewExchangeCodeCase(authcodes AuthCodeStore, tokens TokenService, clientSecret string) *ExchangeCodeCase {
	return &ExchangeCodeCase{authcodes: authcodes, tokens: tokens, clientSecret: clientSecret}
}

func (c *ExchangeCodeCase) Execute(ctx context.Context, code, codeVerifier, clientSecret string) (*TokenResponse, error) {
	authCode, err := c.authcodes.GetAndDelete(ctx, code)
	if err != nil {
		return nil, pkgerrors.ErrNotFound
	}

	if clientSecret != c.clientSecret {
		return nil, pkgerrors.ErrUnauthorized
	}

	h := sha256.Sum256([]byte(codeVerifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	if computed != authCode.CodeChallenge {
		return nil, pkgerrors.ErrInvalidPKCE
	}

	accessToken, refreshToken, err := c.tokens.Issue(ctx, authCode.UserID, authCode.Roles, authCode.TrustScore, authCode.LoginSignals)
	if err != nil {
		return nil, err
	}

	return &TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    900,
	}, nil
}
