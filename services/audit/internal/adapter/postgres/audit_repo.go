package postgres

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zero-trust/zero-trust-auth/services/audit/internal/entities"
	"github.com/zero-trust/zero-trust-auth/services/audit/internal/port"
)

type AuditRepo struct {
	db *pgxpool.Pool
}

var _ port.AuditRepository = (*AuditRepo)(nil)

func NewAuditRepo(db *pgxpool.Pool) *AuditRepo {
	return &AuditRepo{db: db}
}

func (r *AuditRepo) Save(ctx context.Context, e *entities.AuditEvent) error {
	payloadJSON, err := json.Marshal(e.Payload)
	if err != nil {
		return err
	}
	const q = `
		INSERT INTO audit_log (id, event_type, user_id, payload, created_at)
		VALUES ($1, $2, $3, $4, $5)`
	_, err = r.db.Exec(ctx, q, e.ID, e.EventType, e.UserID, payloadJSON, e.CreatedAt)
	return err
}
