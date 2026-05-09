package cases

import (
	"context"

	"github.com/zero-trust/zero-trust-auth/audit/internal/entities"
)

type Cases struct {
	queryEvents *QueryEventsCase
}

func NewCases(queryEvents *QueryEventsCase) *Cases {
	return &Cases{queryEvents: queryEvents}
}

func (c *Cases) QueryEvents(ctx context.Context, f QueryFilter) ([]*entities.AuditEvent, int, error) {
	return c.queryEvents.Execute(ctx, f)
}
