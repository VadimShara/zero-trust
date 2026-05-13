package keycloak

import (
	"context"
	"errors"
	"net/url"
	"strings"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/zero-trust/zero-trust-auth/idpadapter/internal/entities"
	"github.com/zero-trust/zero-trust-auth/idpadapter/internal/cases"
)

type OIDCClient struct {
	provider        *gooidc.Provider
	verifier        *gooidc.IDTokenVerifier
	oauth2Config    *oauth2.Config
	internalBaseURL string
	publicBaseURL   string
}

var _ cases.OIDCProvider = (*OIDCClient)(nil)

func NewOIDCClient(ctx context.Context, issuer, clientID, clientSecret, redirectURI, publicBaseURL string) (*OIDCClient, error) {
	provider, err := gooidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}

	parsed, err := url.Parse(issuer)
	if err != nil {
		return nil, err
	}
	internalBase := parsed.Scheme + "://" + parsed.Host

	return &OIDCClient{
		provider: provider,
		verifier: provider.Verifier(&gooidc.Config{
			ClientID:        clientID,
			SkipIssuerCheck: true,
		}),
		oauth2Config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURI,
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{gooidc.ScopeOpenID, "email", "profile"},
		},
		internalBaseURL: internalBase,
		publicBaseURL:   publicBaseURL,
	}, nil
}

func (c *OIDCClient) AuthorizeURL(state, challenge string) string {
	authURL := c.oauth2Config.Endpoint.AuthURL

	if c.publicBaseURL != "" && c.internalBaseURL != "" {
		authURL = strings.Replace(authURL, c.internalBaseURL, c.publicBaseURL, 1)
	}

	pubConfig := *c.oauth2Config
	pubConfig.Endpoint.AuthURL = authURL

	return pubConfig.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

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
