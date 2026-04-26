package cases

import (
	"context"

	"github.com/zero-trust/zero-trust-auth/services/gateway/internal/port"
)

type RefreshCase struct {
	tokens port.TokenService
}

func NewRefreshCase(tokens port.TokenService) *RefreshCase {
	return &RefreshCase{tokens: tokens}
}

func (c *RefreshCase) Execute(ctx context.Context, refreshToken string, rc port.RequestCtx) (*TokenResponse, error) {
	accessToken, newRefresh, err := c.tokens.Refresh(ctx, refreshToken, rc)
	if err != nil {
		return nil, err
	}
	return &TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefresh,
		TokenType:    "Bearer",
		ExpiresIn:    900,
	}, nil
}
