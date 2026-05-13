package entities

type Signal struct {
	Score  float64 `json:"score"`
	Weight float64 `json:"weight"`
}

type AuthCode struct {
	Code          string
	UserID        string
	Roles         []string
	TrustScore    float64
	LoginSignals  map[string]Signal
	CodeChallenge string
}
