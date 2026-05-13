package entities

import "time"

type OAuthSession struct {
	State         string
	CodeChallenge string
	ClientID      string
	IP            string
	UserAgent     string
	CreatedAt     time.Time

	Fingerprint string

	MFAPending      bool
	PendingUserID   string
	PendingRoles    []string
	PendingTrust    float64
	PendingEmail    string
	PendingSignals  map[string]Signal
}
