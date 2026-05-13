package cases

import "context"

type RevokeCase struct {
	access  AccessTokenStore
	refresh RefreshTokenStore
}

func NewRevokeCase(access AccessTokenStore, refresh RefreshTokenStore) *RevokeCase {
	return &RevokeCase{access: access, refresh: refresh}
}

func (c *RevokeCase) Execute(ctx context.Context, rawToken string, revokeFamily bool) error {
	if err := c.access.Delete(ctx, rawToken); err == nil {
		return nil
	}

	rt, err := c.refresh.Get(ctx, rawToken)
	if err != nil {
		return nil
	}

	if revokeFamily {
		return c.refresh.RevokeFamily(ctx, rt.FamilyID)
	}
	return c.refresh.MarkConsumed(ctx, rawToken)
}
