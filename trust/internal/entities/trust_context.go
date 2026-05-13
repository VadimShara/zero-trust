package entities

import (
	"time"

	"github.com/google/uuid"
)

type TrustContext struct {
	UserID          uuid.UUID
	IPHash          string
	Country         string
	ASN             string
	UserAgent       string
	FingerprintHash string
	Timestamp       time.Time
}
