package cases

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"time"

	"github.com/zero-trust/zero-trust-auth/gateway/internal/entities"
	pkgerrors "github.com/zero-trust/zero-trust-auth/toolkit/pkg/errors"
)

const authcodeTTL = 5 * time.Minute

type ContinueInput struct {
	State  string
	UserID string
	Email  string
	Roles  []string
	ReqCtx RequestCtx
}

type ContinueCase struct {
	sessions  SessionStore
	authcodes AuthCodeStore
	trust     TrustService
}

func NewContinueCase(sessions SessionStore, authcodes AuthCodeStore, trust TrustService) *ContinueCase {
	return &ContinueCase{sessions: sessions, authcodes: authcodes, trust: trust}
}

func (c *ContinueCase) Execute(ctx context.Context, in ContinueInput) error {
	sess, err := c.sessions.Get(ctx, in.State)
	if err != nil {
		return pkgerrors.ErrNotFound
	}

	rc := in.ReqCtx
	if sess.IP != "" {
		rc.IP = sess.IP
	}

	if sess.Fingerprint != "" {
		rc.Fingerprint = sess.Fingerprint
	}

	score, decision, signals, err := c.trust.EvaluateTrust(ctx, in.UserID, in.Roles, rc, false)
	if err != nil {
		return err
	}

	switch decision {
	case "ALLOW":
		_, _, _, _ = c.trust.EvaluateTrust(ctx, in.UserID, in.Roles, rc, true)
		return c.issueCode(ctx, sess, in.UserID, in.Roles, score, signals)

	case "MFA_REQUIRED", "STEP_UP":
		slog.Info("trust requires MFA, suspending flow", "decision", decision, "score", score, "user_id", in.UserID)
		sess.MFAPending = true
		sess.PendingUserID = in.UserID
		sess.PendingRoles = in.Roles
		sess.PendingTrust = score
		sess.PendingEmail = in.Email
		sess.PendingSignals = signals
		return c.sessions.Save(ctx, sess, authcodeTTL)

	default:
		return pkgerrors.ErrTrustDenied
	}
}

func (c *ContinueCase) IssueCodeAfterMFA(ctx context.Context, sess *entities.OAuthSession) error {
	return c.issueCode(ctx, sess, sess.PendingUserID, sess.PendingRoles, sess.PendingTrust, sess.PendingSignals)
}

func (c *ContinueCase) issueCode(ctx context.Context, sess *entities.OAuthSession, userID string, roles []string, score float64, signals map[string]entities.Signal) error {
	code, err := generateCode()
	if err != nil {
		return err
	}
	authCode := &entities.AuthCode{
		Code:          code,
		UserID:        userID,
		Roles:         roles,
		TrustScore:    score,
		LoginSignals:  signals,
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
