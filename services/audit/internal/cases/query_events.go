package cases

import (
	"context"

	"github.com/zero-trust/zero-trust-auth/services/audit/internal/entities"
	"github.com/zero-trust/zero-trust-auth/services/audit/internal/port"
)

type QueryEventsCase struct {
	repo port.AuditRepository
}

func NewQueryEventsCase(repo port.AuditRepository) *QueryEventsCase {
	return &QueryEventsCase{repo: repo}
}

func (c *QueryEventsCase) Execute(ctx context.Context, f port.QueryFilter) ([]*entities.AuditEvent, int, error) {
	return c.repo.Query(ctx, f)
}
