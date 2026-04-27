package cases

import (
	"context"

	"github.com/zero-trust/zero-trust-auth/services/gateway/internal/port"
	pkgerrors "github.com/zero-trust/zero-trust-auth/toolkit/pkg/errors"
)

// MFASetupResult is returned to render the enrollment/challenge page.
type MFASetupResult struct {
	Secret     string
	OTPAuthURI string
	Enrolled   bool // false = show secret for first-time setup
}

type MFACase struct {
	sessions port.SessionStore
	mfa      port.MFAService
	cont     *ContinueCase
}

func NewMFACase(sessions port.SessionStore, mfa port.MFAService, cont *ContinueCase) *MFACase {
	return &MFACase{sessions: sessions, mfa: mfa, cont: cont}
}

// Setup returns TOTP enrollment info for the given state's pending user.
// Called by GET /mfa to render the challenge page.
func (c *MFACase) Setup(ctx context.Context, state string) (*MFASetupResult, error) {
	sess, err := c.sessions.Get(ctx, state)
	if err != nil || !sess.MFAPending {
		return nil, pkgerrors.ErrNotFound
	}
	setup, err := c.mfa.Setup(ctx, sess.PendingUserID, sess.PendingEmail)
	if err != nil {
		return nil, err
	}
	return &MFASetupResult{Secret: setup.Secret, OTPAuthURI: setup.OTPAuthURI, Enrolled: setup.Enrolled}, nil
}

// Verify checks the submitted TOTP code. On success it issues the own_code so
// GET /callback can complete the OAuth flow.
func (c *MFACase) Verify(ctx context.Context, state, code string) error {
	sess, err := c.sessions.Get(ctx, state)
	if err != nil || !sess.MFAPending {
		return pkgerrors.ErrNotFound
	}
	valid, err := c.mfa.Verify(ctx, sess.PendingUserID, code)
	if err != nil {
		return err
	}
	if !valid {
		return pkgerrors.ErrUnauthorized
	}
	// MFA passed — mark session as no longer pending and issue the code.
	sess.MFAPending = false
	if err := c.sessions.Save(ctx, sess, authcodeTTL); err != nil {
		return err
	}
	return c.cont.IssueCodeAfterMFA(ctx, sess)
}
