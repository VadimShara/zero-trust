package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zero-trust/zero-trust-auth/services/trust/internal/port"
)

type DeviceRepo struct {
	db *pgxpool.Pool
}

var _ port.DeviceRepository = (*DeviceRepo)(nil)

func NewDeviceRepo(db *pgxpool.Pool) *DeviceRepo {
	return &DeviceRepo{db: db}
}

func (r *DeviceRepo) IsKnownDevice(ctx context.Context, userID, fingerprintHash string) (bool, error) {
	const q = `
		SELECT EXISTS(
			SELECT 1 FROM trust_device_fingerprints
			WHERE user_id = $1 AND fingerprint_hash = $2
		)`
	var exists bool
	err := r.db.QueryRow(ctx, q, userID, fingerprintHash).Scan(&exists)
	return exists, err
}

func (r *DeviceRepo) SaveDevice(ctx context.Context, userID, fingerprintHash, uaHash string) error {
	const q = `
		INSERT INTO trust_device_fingerprints
			(id, user_id, fingerprint_hash, ua_hash, first_seen, last_seen, seen_count)
		VALUES ($1, $2, $3, $4, $5, $5, 1)
		ON CONFLICT (user_id, fingerprint_hash)
		DO UPDATE SET last_seen = EXCLUDED.last_seen,
		              seen_count = trust_device_fingerprints.seen_count + 1`
	now := time.Now().UTC()
	_, err := r.db.Exec(ctx, q, uuid.New(), userID, fingerprintHash, uaHash, now)
	return err
}
