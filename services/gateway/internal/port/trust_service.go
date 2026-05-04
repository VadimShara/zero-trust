package port

import "context"

type RequestCtx struct {
	IP          string
	UserAgent   string
	Fingerprint string
}

type TrustService interface {
	AnonymousCheck(ctx context.Context, rc RequestCtx) (allow bool, err error)
	// EvaluateTrust scores the request context. register=true tells the trust
	// service to persist the device fingerprint (only on successful login).
	EvaluateTrust(ctx context.Context, userID string, roles []string, rc RequestCtx, register bool) (score float64, decision string, err error)
	IncrFails(ctx context.Context, userID string) error
	ResetFails(ctx context.Context, userID string) error
}
