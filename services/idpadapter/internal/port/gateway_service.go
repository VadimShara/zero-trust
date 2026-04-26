package port

import "context"

type RequestCtx struct {
	IP          string `json:"ip"`
	UserAgent   string `json:"user_agent"`
	Fingerprint string `json:"fingerprint"`
}

type GatewayService interface {
	Continue(ctx context.Context, state, userID string, roles []string, rc RequestCtx) error
}
