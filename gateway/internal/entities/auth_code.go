package entities

type AuthCode struct {
	Code          string
	UserID        string
	Roles         []string
	TrustScore    float64
	CodeChallenge string
}
