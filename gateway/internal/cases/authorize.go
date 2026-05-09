package cases

import (
	"context"
	"errors"
	"time"

	"github.com/zero-trust/zero-trust-auth/gateway/internal/entities"
	pkgerrors "github.com/zero-trust/zero-trust-auth/toolkit/pkg/errors"
)

const sessionTTL = 10 * time.Minute

type AuthorizeCase struct {
	sessions  SessionStore
	trust     TrustService
	idp       IDPAdapterService
	clientID  string // expected CLIENT_ID env value
}

func NewAuthorizeCase(sessions SessionStore, trust TrustService, idp IDPAdapterService, clientID string) *AuthorizeCase {
	return &AuthorizeCase{sessions: sessions, trust: trust, idp: idp, clientID: clientID}
}

// Execute validates the authorize request, stores the session, runs the anonymous
// trust check, and returns the Keycloak login URL to redirect the browser to.
func (c *AuthorizeCase) Execute(ctx context.Context, clientID, codeChallenge, method, state string, rc RequestCtx) (loginURL string, err error) {
	if clientID != c.clientID {
		return "", pkgerrors.ErrUnauthorized
	}
	if method != "S256" {
		return "", errors.New("only S256 code_challenge_method is supported")
	}

	sess := &entities.OAuthSession{
		State:         state,
		CodeChallenge: codeChallenge,
		ClientID:      clientID,
		IP:            rc.IP,
		UserAgent:     rc.UserAgent,
		Fingerprint:   rc.Fingerprint,
		CreatedAt:     time.Now().UTC(),
	}
	if err := c.sessions.Save(ctx, sess, sessionTTL); err != nil {
		return "", err
	}

	allow, err := c.trust.AnonymousCheck(ctx, rc)
	if err != nil || !allow {
		_ = c.sessions.Delete(ctx, state) // cleanup on deny
		return "", pkgerrors.ErrUnauthorized
	}

	return c.idp.GetLoginURL(ctx, state)
}
