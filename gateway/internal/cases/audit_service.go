package cases

import "context"

type AuditEvent struct {
	ID        string         `json:"id"`
	EventType string         `json:"event_type"`
	UserID    *string        `json:"user_id,omitempty"`
	Payload   map[string]any `json:"payload"`
	CreatedAt string         `json:"created_at"`
}

type AuditQueryResult struct {
	Events []AuditEvent `json:"events"`
	Total  int          `json:"total"`
	Limit  int          `json:"limit"`
	Offset int          `json:"offset"`
}

type AuditService interface {
	QueryEvents(ctx context.Context, params map[string]string) (*AuditQueryResult, error)
}
