package cases

import (
	"context"

	"github.com/google/uuid"
)

type Cases struct {
	resolveUser *ResolveUserCase
	mfa         *MFACase
}

func NewCases(resolveUser *ResolveUserCase, mfa *MFACase) *Cases {
	return &Cases{resolveUser: resolveUser, mfa: mfa}
}

func (c *Cases) ResolveUser(ctx context.Context, idp, sub, email string) (uuid.UUID, bool, error) {
	return c.resolveUser.Execute(ctx, idp, sub, email)
}

func (c *Cases) SetupMFA(ctx context.Context, userID, email string) (*SetupResult, error) {
	return c.mfa.Setup(ctx, userID, email)
}

func (c *Cases) VerifyMFA(ctx context.Context, userID, code string) (bool, error) {
	return c.mfa.Verify(ctx, userID, code)
}
