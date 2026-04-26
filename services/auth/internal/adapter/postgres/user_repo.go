package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zero-trust/zero-trust-auth/services/auth/internal/entities"
	"github.com/zero-trust/zero-trust-auth/services/auth/internal/port"
	pkgerrors "github.com/zero-trust/zero-trust-auth/toolkit/pkg/errors"
)

type UserRepo struct {
	db *pgxpool.Pool
}

// compile-time interface check
var _ port.UserRepository = (*UserRepo)(nil)

func NewUserRepo(db *pgxpool.Pool) *UserRepo {
	return &UserRepo{db: db}
}

func (r *UserRepo) FindByIDPSub(ctx context.Context, idp, sub string) (*entities.User, error) {
	const q = `
		SELECT u.id, u.created_at
		FROM users u
		JOIN user_idp_links l ON l.user_id = u.id
		WHERE l.idp = $1 AND l.sub = $2`

	var u entities.User
	err := r.db.QueryRow(ctx, q, idp, sub).Scan(&u.ID, &u.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, pkgerrors.ErrNotFound
		}
		return nil, err
	}
	return &u, nil
}

func (r *UserRepo) CreateUser(ctx context.Context, u *entities.User) error {
	const q = `INSERT INTO users (id, created_at) VALUES ($1, $2)`
	_, err := r.db.Exec(ctx, q, u.ID, u.CreatedAt)
	return err
}

func (r *UserRepo) CreateIDPLink(ctx context.Context, link *entities.UserIDPLink) error {
	const q = `
		INSERT INTO user_idp_links (user_id, idp, sub, email, created_at)
		VALUES ($1, $2, $3, $4, $5)`
	_, err := r.db.Exec(ctx, q, link.UserID, link.IDP, link.Sub, link.Email, link.CreatedAt)
	return err
}
