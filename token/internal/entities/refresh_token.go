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
	Raw      string
	Hash     string
	ATHash   string
	UserID   uuid.UUID
	Roles    []string
	FamilyID uuid.UUID
	Status   Status
	Exp      int64
}

func NewRefreshToken(userID uuid.UUID, roles []string, familyID uuid.UUID, atHash string, ttl time.Duration) *RefreshToken {
	raw := genRaw()
	return &RefreshToken{
		Raw:      raw,
		Hash:     hashHex(raw),
		ATHash:   atHash,
		UserID:   userID,
		Roles:    roles,
		FamilyID: familyID,
		Status:   Active,
		Exp:      time.Now().Add(ttl).Unix(),
	}
}
