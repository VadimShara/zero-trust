package transport

import (
	"context"

	"github.com/zero-trust/zero-trust-auth/audit/internal/cases"
	"github.com/zero-trust/zero-trust-auth/audit/internal/entities"
)

type UseCases interface {
	QueryEvents(ctx context.Context, f cases.QueryFilter) ([]*entities.AuditEvent, int, error)
}
