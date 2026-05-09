package entities

import "github.com/google/uuid"

type TokenFamily struct {
	FamilyID uuid.UUID
	UserID   uuid.UUID
}
