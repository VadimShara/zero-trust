package cases

import (
	"context"
	"fmt"
)

type HandleCallbackCase struct {
	pkce             PKCEStore
	oidc             OIDCProvider
	auth             AuthService
	gateway          GatewayService
	gatewayPublicURL string
}

func NewHandleCallbackCase(
	pkce PKCEStore,
	oidc OIDCProvider,
	auth AuthService,
	gateway GatewayService,
	gatewayPublicURL string,
) *HandleCallbackCase {
	return &HandleCallbackCase{
		pkce:             pkce,
		oidc:             oidc,
		auth:             auth,
		gateway:          gateway,
		gatewayPublicURL: gatewayPublicURL,
	}
}

func (c *HandleCallbackCase) Execute(ctx context.Context, code, state string, rc RequestCtx) (string, error) {
	verifier, err := c.pkce.Get(ctx, state)
	if err != nil {
		return "", fmt.Errorf("pkce verifier not found for state %q: %w", state, err)
	}
	_ = c.pkce.Delete(ctx, state)

	identity, err := c.oidc.Exchange(ctx, code, verifier)
	if err != nil {
		return "", fmt.Errorf("oidc exchange: %w", err)
	}

	userID, err := c.auth.ResolveUser(ctx, identity.Sub, identity.Email, "keycloak")
	if err != nil {
		return "", fmt.Errorf("resolve user: %w", err)
	}

	if err := c.gateway.Continue(ctx, state, userID, identity.Email, identity.Roles, rc); err != nil {
		return "", fmt.Errorf("gateway continue: %w", err)
	}

	return fmt.Sprintf("%s/callback?state=%s", c.gatewayPublicURL, state), nil
}
