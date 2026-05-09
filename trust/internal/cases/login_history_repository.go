package cases

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type LoginRecord struct {
	UserID    uuid.UUID
	IPHash    string
	Country   string
	ASN       string
	Timestamp time.Time
}

type LoginHistoryRepository interface {
	LastLogin(ctx context.Context, userID uuid.UUID) (*LoginRecord, error)
	Save(ctx context.Context, record *LoginRecord) error
}
