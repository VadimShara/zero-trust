package cases

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/zero-trust/zero-trust-auth/audit/internal/entities"
)

type HandleEventCase struct {
	repo AuditRepository
}

func NewHandleEventCase(repo AuditRepository) *HandleEventCase {
	return &HandleEventCase{repo: repo}
}

// Execute deserialises a Kafka message and persists it as an immutable audit log entry.
//
// Event type resolution order:
//  1. "event" field  (used by token/trust services)
//  2. "event_type" field
//  3. msg.Topic as fallback
//
// user_id is optional; omitted for anonymous events (e.g. LoginBlocked).
func (c *HandleEventCase) Execute(ctx context.Context, msg Message) error {
	var raw map[string]any
	if err := json.Unmarshal(msg.Value, &raw); err != nil {
		return err
	}

	eventType := stringField(raw, "event", "event_type")
	if eventType == "" {
		eventType = msg.Topic
	}

	var userID *uuid.UUID
	if uidStr := stringField(raw, "user_id"); uidStr != "" {
		if uid, err := uuid.Parse(uidStr); err == nil {
			userID = &uid
		}
	}

	return c.repo.Save(ctx, &entities.AuditEvent{
		ID:        uuid.New(),
		EventType: eventType,
		UserID:    userID,
		Payload:   raw,
		CreatedAt: time.Now().UTC(),
	})
}

// stringField returns the first non-empty string value found under any of the given keys.
func stringField(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}
