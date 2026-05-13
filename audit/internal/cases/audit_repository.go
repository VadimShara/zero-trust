package cases

import (
	"context"

	"github.com/zero-trust/zero-trust-auth/audit/internal/entities"
)

type QueryFilter struct {
	UserID    string
	EventType string
	From      string
	To        string
	Limit     int
	Offset    int
}

type AuditRepository interface {
	Save(ctx context.Context, e *entities.AuditEvent) error
	Query(ctx context.Context, f QueryFilter) ([]*entities.AuditEvent, int, error)
}
