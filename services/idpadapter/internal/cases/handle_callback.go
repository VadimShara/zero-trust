package cases

import (
	"context"
	"fmt"

	"github.com/zero-trust/zero-trust-auth/services/idpadapter/internal/port"
)

type HandleCallbackCase struct {
	pkce             port.PKCEStore
	oidc             port.OIDCProvider
	auth             port.AuthService
	gateway          port.GatewayService
	gatewayPublicURL string
}

func NewHandleCallbackCase(
	pkce port.PKCEStore,
	oidc port.OIDCProvider,
	auth port.AuthService,
	gateway port.GatewayService,
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

// Execute processes the browser callback from Keycloak after user login.
// Returns the URL the browser should be redirected to (Gateway public /callback).
//
// Flow (ADR-003):
//  1. Retrieve and delete one-time PKCE verifier from Redis
//  2. Exchange idp_code → id_token with Keycloak, verify JWKS signature
//  3. Extract sub, email, roles from id_token
//  4. Map sub → internal user_id via Auth Service
//  5. Notify Gateway on private port (user_id never appears in browser URL)
//  6. Return redirect URL to Gateway /callback?state=state
func (c *HandleCallbackCase) Execute(ctx context.Context, code, state string, rc port.RequestCtx) (string, error) {
	verifier, err := c.pkce.Get(ctx, state)
	if err != nil {
		return "", fmt.Errorf("pkce verifier not found for state %q: %w", state, err)
	}
	_ = c.pkce.Delete(ctx, state) // one-time use — delete immediately

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
