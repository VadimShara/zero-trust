package cases

import (
	"context"

	pkgerrors "github.com/zero-trust/zero-trust-auth/toolkit/pkg/errors"
)

type MFASetupResult struct {
	Secret     string
	OTPAuthURI string
	Enrolled   bool
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

	rc := RequestCtx{IP: sess.IP, UserAgent: sess.UserAgent, Fingerprint: sess.Fingerprint}
	_, _, _, _ = c.trust.EvaluateTrust(ctx, sess.PendingUserID, sess.PendingRoles, rc, true)

	sess.MFAPending = false
	if err := c.sessions.Save(ctx, sess, authcodeTTL); err != nil {
		return err
	}

	return c.cont.IssueCodeAfterMFA(ctx, sess)
}
