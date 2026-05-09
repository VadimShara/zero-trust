package cases

import (
	"context"

)

type RefreshCase struct {
	tokens TokenService
}

func NewRefreshCase(tokens TokenService) *RefreshCase {
	return &RefreshCase{tokens: tokens}
}

func (c *RefreshCase) Execute(ctx context.Context, refreshToken string, rc RequestCtx) (*TokenResponse, error) {
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
