package entities

import (
	"time"

	"github.com/google/uuid"
)

type UserIDPLink struct {
	UserID    uuid.UUID
	IDP       string
	Sub       string
	Email     string
	CreatedAt time.Time
}
