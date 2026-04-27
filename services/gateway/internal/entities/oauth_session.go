package entities

import "time"

type OAuthSession struct {
	State         string
	CodeChallenge string
	ClientID      string
	IP            string
	UserAgent     string
	CreatedAt     time.Time

	// Set by ContinueCase when trust decision is MFA_REQUIRED.
	// The browser is held at GET /mfa until the user verifies the TOTP code.
	MFAPending    bool
	PendingUserID string
	PendingRoles  []string
	PendingTrust  float64
	PendingEmail  string // shown on TOTP enrollment page
}
