package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zero-trust/zero-trust-auth/audit/internal/cases"
	"github.com/zero-trust/zero-trust-auth/audit/internal/entities"
)

type AuditRepo struct {
	db *pgxpool.Pool
}

var _ cases.AuditRepository = (*AuditRepo)(nil)

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

func (r *AuditRepo) Query(ctx context.Context, f cases.QueryFilter) ([]*entities.AuditEvent, int, error) {
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}

	where := []string{"1=1"}
	args := []any{}
	n := 1

	if f.UserID != "" {
		where = append(where, fmt.Sprintf("user_id = $%d", n))
		args = append(args, f.UserID)
		n++
	}
	if f.EventType != "" {
		where = append(where, fmt.Sprintf("event_type = $%d", n))
		args = append(args, f.EventType)
		n++
	}
	if f.From != "" {
		where = append(where, fmt.Sprintf("created_at >= $%d", n))
		args = append(args, f.From)
		n++
	}
	if f.To != "" {
		where = append(where, fmt.Sprintf("created_at <= $%d", n))
		args = append(args, f.To)
		n++
	}

	cond := strings.Join(where, " AND ")

	var total int
	countQ := fmt.Sprintf("SELECT COUNT(*) FROM audit_log WHERE %s", cond)
	if err := r.db.QueryRow(ctx, countQ, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	dataQ := fmt.Sprintf(`
		SELECT id, event_type, user_id, payload, created_at
		FROM audit_log
		WHERE %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`, cond, n, n+1)
	args = append(args, f.Limit, f.Offset)

	rows, err := r.db.Query(ctx, dataQ, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var events []*entities.AuditEvent
	for rows.Next() {
		var e entities.AuditEvent
		var rawPayload []byte
		if err := rows.Scan(&e.ID, &e.EventType, &e.UserID, &rawPayload, &e.CreatedAt); err != nil {
			return nil, 0, err
		}
		_ = json.Unmarshal(rawPayload, &e.Payload)
		events = append(events, &e)
	}
	return events, total, rows.Err()
}
