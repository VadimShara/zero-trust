package cases

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/zero-trust/zero-trust-auth/auth/internal/entities"
	pkgerrors "github.com/zero-trust/zero-trust-auth/toolkit/pkg/errors"
)

type ResolveUserCase struct {
	repo UserRepository
}

func NewResolveUserCase(repo UserRepository) *ResolveUserCase {
	return &ResolveUserCase{repo: repo}
}

func (c *ResolveUserCase) Execute(ctx context.Context, idp, sub, email string) (userID uuid.UUID, created bool, err error) {
	user, err := c.repo.FindByIDPSub(ctx, idp, sub)
	if err == nil {
		return user.ID, false, nil
	}

	if !errors.Is(err, pkgerrors.ErrNotFound) {
		return uuid.Nil, false, err
	}

	now := time.Now().UTC()
	newUser := &entities.User{
		ID:        uuid.New(),
		CreatedAt: now,
	}

	if err = c.repo.CreateUser(ctx, newUser); err != nil {
		return uuid.Nil, false, err
	}

	link := &entities.UserIDPLink{
		UserID:    newUser.ID,
		IDP:       idp,
		Sub:       sub,
		Email:     email,
		CreatedAt: now,
	}

	if err = c.repo.CreateIDPLink(ctx, link); err != nil {
		return uuid.Nil, false, err
	}

	return newUser.ID, true, nil
}
