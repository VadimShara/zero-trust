package postgres

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zero-trust/zero-trust-auth/trust/internal/cases"
	pkgerrors "github.com/zero-trust/zero-trust-auth/toolkit/pkg/errors"
)

type LoginHistoryRepo struct {
	db *pgxpool.Pool
}

var _ cases.LoginHistoryRepository = (*LoginHistoryRepo)(nil)

func NewLoginHistoryRepo(db *pgxpool.Pool) *LoginHistoryRepo {
	return &LoginHistoryRepo{db: db}
}

func (r *LoginHistoryRepo) LastLogin(ctx context.Context, userID uuid.UUID) (*cases.LoginRecord, error) {
	const q = `
		SELECT user_id, ip_hash, country, asn, timestamp
		FROM trust_login_history
		WHERE user_id = $1
		ORDER BY timestamp DESC
		LIMIT 1`

	var rec cases.LoginRecord
	var country, asn *string
	err := r.db.QueryRow(ctx, q, userID).Scan(
		&rec.UserID, &rec.IPHash, &country, &asn, &rec.Timestamp,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, pkgerrors.ErrNotFound
		}
		return nil, err
	}
	if country != nil {
		rec.Country = *country
	}
	if asn != nil {
		rec.ASN = *asn
	}
	return &rec, nil
}

func (r *LoginHistoryRepo) Save(ctx context.Context, record *cases.LoginRecord) error {
	const q = `
		INSERT INTO trust_login_history
			(id, user_id, ip_hash, country, asn, timestamp, was_successful)
		VALUES ($1, $2, $3, $4, $5, $6, true)`
	_, err := r.db.Exec(ctx, q,
		uuid.New(), record.UserID, record.IPHash,
		record.Country, record.ASN, record.Timestamp,
	)
	return err
}
