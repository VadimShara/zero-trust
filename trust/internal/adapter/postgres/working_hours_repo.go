package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type WorkingHoursRepo struct {
	db *pgxpool.Pool
}

func NewWorkingHoursRepo(db *pgxpool.Pool) *WorkingHoursRepo {
	return &WorkingHoursRepo{db: db}
}

func (r *WorkingHoursRepo) Get(ctx context.Context, userID uuid.UUID) (start, end int, err error) {
	const q = `SELECT typical_start, typical_end FROM trust_working_hours WHERE user_id = $1`
	err = r.db.QueryRow(ctx, q, userID).Scan(&start, &end)
	if err != nil {
		return 8, 20, nil
	}
	return start, end, nil
}
