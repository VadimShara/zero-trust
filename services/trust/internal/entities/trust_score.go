package entities

type Decision string

const (
	Allow       Decision = "ALLOW"
	MFARequired Decision = "MFA_REQUIRED"
	StepUp      Decision = "STEP_UP"
	Deny        Decision = "DENY"
)

type TrustScore struct {
	Value    float64
	Decision Decision
	Signals  []RiskSignal
}

func (t TrustScore) Decide() Decision {
	switch {
	case t.Value >= 0.80:
		return Allow
	case t.Value >= 0.50:
		return MFARequired
	case t.Value >= 0.30:
		return StepUp
	default:
		return Deny
	}
}
