package cases

import (
	"context"
	"fmt"

	"github.com/zero-trust/zero-trust-auth/services/gateway/internal/port"
	pkgerrors "github.com/zero-trust/zero-trust-auth/toolkit/pkg/errors"
)

const mfaPath = "/mfa"

type CallbackCase struct {
	sessions          port.SessionStore
	authcodes         port.AuthCodeStore
	clientCallbackURL string
}

func NewCallbackCase(sessions port.SessionStore, authcodes port.AuthCodeStore, clientCallbackURL string) *CallbackCase {
	return &CallbackCase{sessions: sessions, authcodes: authcodes, clientCallbackURL: clientCallbackURL}
}

// CallbackResult tells the handler which action to take.
type CallbackResult struct {
	MFARequired bool   // true → redirect to /mfa?state=
	RedirectURL string // set when MFARequired is false
}

// Execute inspects session state and returns what to do next.
// If MFA is pending, the browser must visit /mfa before getting the code.
func (c *CallbackCase) Execute(ctx context.Context, gatewayPublicURL, state string) (*CallbackResult, error) {
	sess, err := c.sessions.Get(ctx, state)
	if err != nil {
		return nil, pkgerrors.ErrNotFound
	}

	if sess.MFAPending {
		return &CallbackResult{
			MFARequired: true,
			RedirectURL: fmt.Sprintf("%s%s?state=%s", gatewayPublicURL, mfaPath, state),
		}, nil
	}

	code, err := c.authcodes.GetByState(ctx, state)
	if err != nil {
		return nil, pkgerrors.ErrNotFound
	}
	return &CallbackResult{
		RedirectURL: fmt.Sprintf("%s?code=%s&state=%s", c.clientCallbackURL, code, state),
	}, nil
}
