package cases

import (
	"context"

	"github.com/zero-trust/zero-trust-auth/services/gateway/internal/port"
)

type LogoutCase struct {
	tokens port.TokenService
}

func NewLogoutCase(tokens port.TokenService) *LogoutCase {
	return &LogoutCase{tokens: tokens}
}

func (c *LogoutCase) Execute(ctx context.Context, token string, revokeAll bool) error {
	return c.tokens.Revoke(ctx, token, revokeAll)
}
