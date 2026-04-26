package entities

import "time"

type OAuthSession struct {
	State         string
	CodeChallenge string
	ClientID      string
	IP            string
	UserAgent     string
	CreatedAt     time.Time
}
