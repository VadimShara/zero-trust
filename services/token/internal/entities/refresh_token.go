package entities

import (
	"time"

	"github.com/google/uuid"
)

type Status string

const (
	Active   Status = "ACTIVE"
	Consumed Status = "CONSUMED"
	Revoked  Status = "REVOKED"
)

type RefreshToken struct {
	Raw      string    // random hex — returned to client, never persisted
	Hash     string    // sha256(Raw) — used as Redis key suffix
	UserID   uuid.UUID
	Roles    []string  // carried for access token re-issuance on rotation
	FamilyID uuid.UUID
	Status   Status
	Exp      int64
}

func NewRefreshToken(userID uuid.UUID, roles []string, familyID uuid.UUID, ttl time.Duration) *RefreshToken {
	raw := genRaw() // reuses genRaw from access_token.go (same package)
	return &RefreshToken{
		Raw:      raw,
		Hash:     hashHex(raw),
		UserID:   userID,
		Roles:    roles,
		FamilyID: familyID,
		Status:   Active,
		Exp:      time.Now().Add(ttl).Unix(),
	}
}
