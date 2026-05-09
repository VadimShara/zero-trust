package entities

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/google/uuid"
)

type AccessToken struct {
	Raw        string    // random hex — returned to client, never persisted
	Hash       string    // sha256(Raw) — used as Redis key suffix
	UserID     uuid.UUID
	Roles      []string
	TrustScore float64
	FamilyID   uuid.UUID
	Exp        int64 // unix timestamp
}

func NewAccessToken(userID uuid.UUID, roles []string, trustScore float64, familyID uuid.UUID, ttl time.Duration) *AccessToken {
	raw := genRaw()
	return &AccessToken{
		Raw:        raw,
		Hash:       hashHex(raw),
		UserID:     userID,
		Roles:      roles,
		TrustScore: trustScore,
		FamilyID:   familyID,
		Exp:        time.Now().Add(ttl).Unix(),
	}
}

func genRaw() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func hashHex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
