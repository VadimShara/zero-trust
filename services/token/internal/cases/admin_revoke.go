package cases

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/zero-trust/zero-trust-auth/services/token/internal/port"
)

type AdminRevokeCase struct {
	family  port.TokenFamilyStore
	refresh port.RefreshTokenStore
	events  port.EventPublisher
}

func NewAdminRevokeCase(family port.TokenFamilyStore, refresh port.RefreshTokenStore, events port.EventPublisher) *AdminRevokeCase {
	return &AdminRevokeCase{family: family, refresh: refresh, events: events}
}

// RevokeUser immediately invalidates all token families for the given user.
// Called by admins in incident response — e.g. account compromise.
func (c *AdminRevokeCase) RevokeUser(ctx context.Context, userID uuid.UUID, adminID, reason string) (int, error) {
	families, err := c.family.GetUserFamilies(ctx, userID)
	if err != nil {
		return 0, err
	}

	revoked := 0
	for _, fid := range families {
		_ = c.family.MarkRevoked(ctx, fid)    // blocks all introspects immediately
		_ = c.refresh.RevokeFamily(ctx, fid)  // marks refresh tokens as Revoked
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
