package cases

import (
	"context"

	pkgerrors "github.com/zero-trust/zero-trust-auth/toolkit/pkg/errors"
)

// MFASetupResult is returned to render the enrollment/challenge page.
type MFASetupResult struct {
	Secret     string
	OTPAuthURI string
	Enrolled   bool // false = show secret for first-time setup
}

type MFACase struct {
	sessions SessionStore
	mfa      MFAService
	cont     *ContinueCase
	trust    TrustService
}

func NewMFACase(sessions SessionStore, mfa MFAService, cont *ContinueCase, trust TrustService) *MFACase {
	return &MFACase{sessions: sessions, mfa: mfa, cont: cont, trust: trust}
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
	// MFA passed — reset fail counter (may have been set by Keycloak login failures).
	_ = c.trust.ResetFails(ctx, sess.PendingUserID)
	sess.MFAPending = false
	if err := c.sessions.Save(ctx, sess, authcodeTTL); err != nil {
		return err
	}
	return c.cont.IssueCodeAfterMFA(ctx, sess)
}
