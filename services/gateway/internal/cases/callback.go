package cases

import (
	"context"
	"fmt"

	"github.com/zero-trust/zero-trust-auth/services/gateway/internal/port"
	pkgerrors "github.com/zero-trust/zero-trust-auth/toolkit/pkg/errors"
)

type CallbackCase struct {
	authcodes         port.AuthCodeStore
	clientCallbackURL string
}

func NewCallbackCase(authcodes port.AuthCodeStore, clientCallbackURL string) *CallbackCase {
	return &CallbackCase{authcodes: authcodes, clientCallbackURL: clientCallbackURL}
}

// Execute returns the URL to redirect the browser to (client app /callback).
// The own_code was stored by ContinueCase; this call is the browser's second hit
// after IDPAdapter redirected it here with just ?state=.
func (c *CallbackCase) Execute(ctx context.Context, state string) (string, error) {
	code, err := c.authcodes.GetByState(ctx, state)
	if err != nil {
		return "", pkgerrors.ErrNotFound
	}
	return fmt.Sprintf("%s?code=%s&state=%s", c.clientCallbackURL, code, state), nil
}
