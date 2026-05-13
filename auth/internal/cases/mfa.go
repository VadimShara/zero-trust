package cases

import (
	"context"

	"github.com/pquerna/otp/totp"

	pkgerrors "github.com/zero-trust/zero-trust-auth/toolkit/pkg/errors"
)

type MFACase struct {
	users  UserRepository
	issuer string
}

func NewMFACase(users UserRepository, issuer string) *MFACase {
	return &MFACase{users: users, issuer: issuer}
}

type SetupResult struct {
	Secret     string
	OTPAuthURI string
	Enrolled   bool
}

func (c *MFACase) Setup(ctx context.Context, userID, email string) (*SetupResult, error) {
	secret, err := c.users.GetTOTPSecret(ctx, userID)
	if err == nil {
		enrolled, _ := c.users.IsTOTPEnrolled(ctx, userID)
		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      c.issuer,
			AccountName: email,
			Secret:      []byte(secret),
		})
		if err != nil {
			return nil, err
		}
		return &SetupResult{Secret: secret, OTPAuthURI: key.URL(), Enrolled: enrolled}, nil
	}

	if err != pkgerrors.ErrNotFound {
		return nil, err
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      c.issuer,
		AccountName: email,
	})
	if err != nil {
		return nil, err
	}

	if err := c.users.SetTOTPSecret(ctx, userID, key.Secret()); err != nil {
		return nil, err
	}

	return &SetupResult{Secret: key.Secret(), OTPAuthURI: key.URL(), Enrolled: false}, nil
}

func (c *MFACase) Verify(ctx context.Context, userID, code string) (bool, error) {
	secret, err := c.users.GetTOTPSecret(ctx, userID)
	if err != nil {
		if err == pkgerrors.ErrNotFound {
			return false, nil
		}
		return false, err
	}

	if !totp.Validate(code, secret) {
		return false, nil
	}

	enrolled, _ := c.users.IsTOTPEnrolled(ctx, userID)
	if !enrolled {
		_ = c.users.SetTOTPEnrolled(ctx, userID)
	}

	return true, nil
}
