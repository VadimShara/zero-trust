package cases

import (
	"context"
	"net/url"
)

type Cases struct {
	getLoginURL       *GetLoginURLCase
	handleCallback    *HandleCallbackCase
	keycloakIssuer    string
	keycloakPublicURL string
	keycloakClientID  string
}

func NewCases(
	getLoginURL *GetLoginURLCase,
	handleCallback *HandleCallbackCase,
	keycloakIssuer string,
	keycloakPublicURL string,
	keycloakClientID string,
) *Cases {
	return &Cases{
		getLoginURL:       getLoginURL,
		handleCallback:    handleCallback,
		keycloakIssuer:    keycloakIssuer,
		keycloakPublicURL: keycloakPublicURL,
		keycloakClientID:  keycloakClientID,
	}
}

func (c *Cases) GetLoginURL(ctx context.Context, state string) (string, error) {
	return c.getLoginURL.Execute(ctx, state)
}

func (c *Cases) HandleCallback(ctx context.Context, code, state string, rc RequestCtx) (string, error) {
	return c.handleCallback.Execute(ctx, code, state, rc)
}

func (c *Cases) GetLogoutURL(postLogoutRedirectURI string) string {
	base := c.keycloakPublicURL
	if parsed, err := url.Parse(c.keycloakIssuer); err == nil {
		base = c.keycloakPublicURL + parsed.Path
	}
	return base + "/protocol/openid-connect/logout" +
		"?client_id=" + url.QueryEscape(c.keycloakClientID) +
		"&post_logout_redirect_uri=" + url.QueryEscape(postLogoutRedirectURI)
}
