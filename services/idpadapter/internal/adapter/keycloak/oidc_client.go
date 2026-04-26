package keycloak

import (
	"context"
	"errors"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/zero-trust/zero-trust-auth/services/idpadapter/internal/entities"
	"github.com/zero-trust/zero-trust-auth/services/idpadapter/internal/port"
)

// OIDCClient implements port.OIDCProvider against Keycloak (or any OIDC-compliant IDP).
// It fetches the discovery document on init and keeps the provider in memory.
type OIDCClient struct {
	provider     *gooidc.Provider
	verifier     *gooidc.IDTokenVerifier
	oauth2Config *oauth2.Config
}

var _ port.OIDCProvider = (*OIDCClient)(nil)

// NewOIDCClient fetches the OIDC discovery document from issuer and builds
// the oauth2 config. ctx is used only for the discovery request.
func NewOIDCClient(ctx context.Context, issuer, clientID, clientSecret, redirectURI string) (*OIDCClient, error) {
	provider, err := gooidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}
	return &OIDCClient{
		provider: provider,
		verifier: provider.Verifier(&gooidc.Config{ClientID: clientID}),
		oauth2Config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURI,
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{gooidc.ScopeOpenID, "email", "profile"},
		},
	}, nil
}

// AuthorizeURL builds the Keycloak authorization URL with S256 PKCE.
func (c *OIDCClient) AuthorizeURL(state, challenge string) string {
	return c.oauth2Config.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

// Exchange exchanges the authorization code for an id_token, verifies its
// signature via JWKS, and returns the extracted identity.
func (c *OIDCClient) Exchange(ctx context.Context, code, verifier string) (*entities.IDPIdentity, error) {
	token, err := c.oauth2Config.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", verifier),
	)
	if err != nil {
		return nil, err
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("keycloak: no id_token in token response")
	}

	idToken, err := c.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, err
	}

	// Standard + Keycloak-specific claims
	var claims struct {
		Sub         string `json:"sub"`
		Email       string `json:"email"`
		RealmAccess struct {
			Roles []string `json:"roles"`
		} `json:"realm_access"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, err
	}

	return &entities.IDPIdentity{
		Sub:   claims.Sub,
		Email: claims.Email,
		Roles: claims.RealmAccess.Roles,
	}, nil
}
