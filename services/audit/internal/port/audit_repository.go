package port

import (
	"context"

	"github.com/zero-trust/zero-trust-auth/services/audit/internal/entities"
)

type AuditRepository interface {
	Save(ctx context.Context, e *entities.AuditEvent) error
}
