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

func (t TrustScore) Decide(allow, mfaRequired, stepUp float64) Decision {
	switch {
	case t.Value >= allow:
		return Allow
	case t.Value >= mfaRequired:
		return MFARequired
	case t.Value >= stepUp:
		return StepUp
	default:
		return Deny
	}
}
