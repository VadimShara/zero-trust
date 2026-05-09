package cases

import "context"

type Cases struct {
	getLoginURL    *GetLoginURLCase
	handleCallback *HandleCallbackCase
}

func NewCases(getLoginURL *GetLoginURLCase, handleCallback *HandleCallbackCase) *Cases {
	return &Cases{getLoginURL: getLoginURL, handleCallback: handleCallback}
}

func (c *Cases) GetLoginURL(ctx context.Context, state string) (string, error) {
	return c.getLoginURL.Execute(ctx, state)
}

func (c *Cases) HandleCallback(ctx context.Context, code, state string, rc RequestCtx) (string, error) {
	return c.handleCallback.Execute(ctx, code, state, rc)
}
