package cases

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/zero-trust/zero-trust-auth/services/gateway/internal/entities"
	"github.com/zero-trust/zero-trust-auth/services/gateway/internal/port"
	pkgerrors "github.com/zero-trust/zero-trust-auth/toolkit/pkg/errors"
)

const authcodeTTL = 60 * time.Second

type ContinueInput struct {
	State   string
	UserID  string
	Roles   []string
	ReqCtx  port.RequestCtx
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
// It evaluates trust, generates own_code, and stores it so GET /callback can redirect
// the browser to the client with the code.
func (c *ContinueCase) Execute(ctx context.Context, in ContinueInput) error {
	sess, err := c.sessions.Get(ctx, in.State)
	if err != nil {
		return pkgerrors.ErrNotFound
	}

	score, decision, err := c.trust.EvaluateTrust(ctx, in.UserID, in.Roles, in.ReqCtx)
	if err != nil {
		return err
	}
	if decision != "ALLOW" {
		return pkgerrors.ErrTrustDenied
	}

	code, err := generateCode()
	if err != nil {
		return err
	}

	authCode := &entities.AuthCode{
		Code:          code,
		UserID:        in.UserID,
		Roles:         in.Roles,
		TrustScore:    score,
		CodeChallenge: sess.CodeChallenge,
	}
	if err := c.authcodes.Save(ctx, authCode, authcodeTTL); err != nil {
		return err
	}
	// Store state→code so GET /callback can retrieve it.
	return c.authcodes.SaveByState(ctx, in.State, code, authcodeTTL)
}

func generateCode() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
