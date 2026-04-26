package entities

import (
	"time"

	"github.com/google/uuid"
)

type AuditEvent struct {
	ID        uuid.UUID
	EventType string
	UserID    *uuid.UUID     // nullable — some events are anonymous (e.g. LoginBlocked)
	Payload   map[string]any
	CreatedAt time.Time
}
