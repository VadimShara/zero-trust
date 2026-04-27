package port

import "context"

type MFASetup struct {
	Secret     string
	OTPAuthURI string
	Enrolled   bool
}

type MFAService interface {
	Setup(ctx context.Context, userID, email string) (*MFASetup, error)
	Verify(ctx context.Context, userID, code string) (bool, error)
}
