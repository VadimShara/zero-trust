package entities

import (
	"time"

	"github.com/google/uuid"
)

type AuditEvent struct {
	ID        uuid.UUID
	EventType string
	UserID    *uuid.UUID
	Payload   map[string]any
	CreatedAt time.Time
}
