package cases

import (
	"context"
)

type RevokeCase struct {
	access  AccessTokenStore
	refresh RefreshTokenStore
}

func NewRevokeCase(access AccessTokenStore, refresh RefreshTokenStore) *RevokeCase {
	return &RevokeCase{access: access, refresh: refresh}
}

func (c *RevokeCase) Execute(ctx context.Context, rawToken string, revokeFamily bool) error {
	// Try access token first.
	if err := c.access.Delete(ctx, rawToken); err == nil {
		// Access token deleted. If revoke_family, also nuke all refresh tokens.
		if revokeFamily {
			// We don't have familyID from access token alone here;
			// caller should also pass the refresh token in that case.
			// For logout (single token), deleting the access token is sufficient.
		}
		return nil
	}

	// Try refresh token.
	rt, err := c.refresh.Get(ctx, rawToken)
	if err != nil {
		return nil // token not found — treat as already revoked
	}

	if revokeFamily {
		return c.refresh.RevokeFamily(ctx, rt.FamilyID)
	}
	return c.refresh.MarkConsumed(ctx, rawToken)
}
