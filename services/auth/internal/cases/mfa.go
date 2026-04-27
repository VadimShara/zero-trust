package cases

import (
	"context"

	"github.com/pquerna/otp/totp"

	"github.com/zero-trust/zero-trust-auth/services/auth/internal/port"
	pkgerrors "github.com/zero-trust/zero-trust-auth/toolkit/pkg/errors"
)

type MFACase struct {
	users   port.UserRepository
	issuer  string
}

func NewMFACase(users port.UserRepository, issuer string) *MFACase {
	return &MFACase{users: users, issuer: issuer}
}

// SetupResult is returned when a user enrolls for the first time.
type SetupResult struct {
	Secret     string
	OTPAuthURI string
	Enrolled   bool // false = first time setup, true = already enrolled
}

// Setup returns the existing TOTP secret or generates a new one.
// The OTPAuthURI can be used to display a QR code.
func (c *MFACase) Setup(ctx context.Context, userID, email string) (*SetupResult, error) {
	secret, err := c.users.GetTOTPSecret(ctx, userID)
	if err == nil {
		// Already enrolled — return URI without exposing secret again.
		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      c.issuer,
			AccountName: email,
			Secret:      []byte(secret),
		})
		if err != nil {
			return nil, err
		}
		return &SetupResult{Secret: secret, OTPAuthURI: key.URL(), Enrolled: true}, nil
	}
	if err != pkgerrors.ErrNotFound {
		return nil, err
	}

	// First-time setup: generate a new secret.
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

// Verify checks a 6-digit TOTP code against the user's stored secret.
func (c *MFACase) Verify(ctx context.Context, userID, code string) (bool, error) {
	secret, err := c.users.GetTOTPSecret(ctx, userID)
	if err != nil {
		if err == pkgerrors.ErrNotFound {
			return false, nil
		}
		return false, err
	}
	return totp.Validate(code, secret), nil
}
