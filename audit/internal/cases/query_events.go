package cases

import (
	"context"

	"github.com/zero-trust/zero-trust-auth/audit/internal/entities"
)

type QueryEventsCase struct {
	repo AuditRepository
}

func NewQueryEventsCase(repo AuditRepository) *QueryEventsCase {
	return &QueryEventsCase{repo: repo}
}

func (c *QueryEventsCase) Execute(ctx context.Context, f QueryFilter) ([]*entities.AuditEvent, int, error) {
	return c.repo.Query(ctx, f)
}
