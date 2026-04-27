package cases

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"time"

	"github.com/zero-trust/zero-trust-auth/services/gateway/internal/entities"
	"github.com/zero-trust/zero-trust-auth/services/gateway/internal/port"
	pkgerrors "github.com/zero-trust/zero-trust-auth/toolkit/pkg/errors"
)

const authcodeTTL = 5 * time.Minute // 60s is too short for manual testing; spec says 60s for production

type ContinueInput struct {
	State  string
	UserID string
	Email  string
	Roles  []string
	ReqCtx port.RequestCtx
}

type ContinueCase struct {
	sessions  port.SessionStore
	authcodes port.AuthCodeStore
	trust     port.TrustService
}

func NewContinueCase(sessions port.SessionStore, authcodes port.AuthCodeStore, trust port.TrustService) *ContinueCase {
	return &ContinueCase{sessions: sessions, authcodes: authcodes, trust: trust}
}

// Execute is called by the private port (:8081) after IDPAdapter resolves user identity.
// On ALLOW it generates own_code immediately.
// On MFA_REQUIRED it saves the pending user info in the session so GET /mfa can challenge the user.
func (c *ContinueCase) Execute(ctx context.Context, in ContinueInput) error {
	sess, err := c.sessions.Get(ctx, in.State)
	if err != nil {
		return pkgerrors.ErrNotFound
	}

	score, decision, err := c.trust.EvaluateTrust(ctx, in.UserID, in.Roles, in.ReqCtx)
	if err != nil {
		return err
	}

	switch decision {
	case "ALLOW":
		return c.issueCode(ctx, sess, in.UserID, in.Roles, score)

	case "MFA_REQUIRED", "STEP_UP":
		slog.Info("trust requires MFA, suspending flow", "decision", decision, "score", score, "user_id", in.UserID)
		sess.MFAPending = true
		sess.PendingUserID = in.UserID
		sess.PendingRoles = in.Roles
		sess.PendingTrust = score
		sess.PendingEmail = in.Email
		// Extend session TTL to give the user time to complete MFA.
		return c.sessions.Save(ctx, sess, authcodeTTL)

	default: // DENY
		return pkgerrors.ErrTrustDenied
	}
}

// IssueCodeAfterMFA is called by MFACase after successful TOTP verification.
func (c *ContinueCase) IssueCodeAfterMFA(ctx context.Context, sess *entities.OAuthSession) error {
	return c.issueCode(ctx, sess, sess.PendingUserID, sess.PendingRoles, sess.PendingTrust)
}

func (c *ContinueCase) issueCode(ctx context.Context, sess *entities.OAuthSession, userID string, roles []string, score float64) error {
	code, err := generateCode()
	if err != nil {
		return err
	}
	authCode := &entities.AuthCode{
		Code:          code,
		UserID:        userID,
		Roles:         roles,
		TrustScore:    score,
		CodeChallenge: sess.CodeChallenge,
	}
	if err := c.authcodes.Save(ctx, authCode, authcodeTTL); err != nil {
		return err
	}
	return c.authcodes.SaveByState(ctx, sess.State, code, authcodeTTL)
}

func generateCode() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
