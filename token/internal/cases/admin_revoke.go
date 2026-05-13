package cases

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type AdminRevokeCase struct {
	family  TokenFamilyStore
	refresh RefreshTokenStore
	events  EventPublisher
}

func NewAdminRevokeCase(family TokenFamilyStore, refresh RefreshTokenStore, events EventPublisher) *AdminRevokeCase {
	return &AdminRevokeCase{family: family, refresh: refresh, events: events}
}

func (c *AdminRevokeCase) RevokeUser(ctx context.Context, userID uuid.UUID, adminID, reason string) (int, error) {
	families, err := c.family.GetUserFamilies(ctx, userID)
	if err != nil {
		return 0, err
	}

	revoked := 0
	for _, fid := range families {
		_ = c.family.MarkRevoked(ctx, fid)
		_ = c.refresh.RevokeFamily(ctx, fid)
		revoked++
	}

	_ = c.events.Publish(ctx, "admin.events", map[string]any{
		"event":       "AdminRevokeUser",
		"target_user": userID,
		"admin_id":    adminID,
		"reason":      reason,
		"families":    revoked,
		"timestamp":   time.Now().UTC(),
	})

	return revoked, nil
}
