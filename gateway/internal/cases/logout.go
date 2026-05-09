package cases

import (
	"context"

)

type LogoutCase struct {
	tokens TokenService
}

func NewLogoutCase(tokens TokenService) *LogoutCase {
	return &LogoutCase{tokens: tokens}
}

func (c *LogoutCase) Execute(ctx context.Context, token string, revokeAll bool) error {
	return c.tokens.Revoke(ctx, token, revokeAll)
}
