package entities

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/google/uuid"
)

type Signal struct {
	Score  float64 `json:"score"`
	Weight float64 `json:"weight"`
}

type AccessToken struct {
	Raw          string
	Hash         string
	UserID       uuid.UUID
	Roles        []string
	TrustScore   float64
	LoginSignals map[string]Signal
	FamilyID     uuid.UUID
	Exp          int64
}

func NewAccessToken(userID uuid.UUID, roles []string, trustScore float64, loginSignals map[string]Signal, familyID uuid.UUID, ttl time.Duration) *AccessToken {
	raw := genRaw()
	return &AccessToken{
		Raw:          raw,
		Hash:         hashHex(raw),
		UserID:       userID,
		Roles:        roles,
		TrustScore:   trustScore,
		LoginSignals: loginSignals,
		FamilyID:     familyID,
		Exp:          time.Now().Add(ttl).Unix(),
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
