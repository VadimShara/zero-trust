package cases

import "context"

type AuthFlow struct {
	authorize *AuthorizeCase
	cont      *ContinueCase
	callback  *CallbackCase
	mfa       *MFACase
	exchange  *ExchangeCodeCase
	refresh   *RefreshCase
	logout    *LogoutCase
}

func NewAuthFlow(
	authorize *AuthorizeCase,
	cont *ContinueCase,
	callback *CallbackCase,
	mfa *MFACase,
	exchange *ExchangeCodeCase,
	refresh *RefreshCase,
	logout *LogoutCase,
) *AuthFlow {
	return &AuthFlow{
		authorize: authorize,
		cont:      cont,
		callback:  callback,
		mfa:       mfa,
		exchange:  exchange,
		refresh:   refresh,
		logout:    logout,
	}
}

func (f *AuthFlow) Authorize(ctx context.Context, clientID, codeChallenge, method, state string, rc RequestCtx) (string, error) {
	return f.authorize.Execute(ctx, clientID, codeChallenge, method, state, rc)
}

func (f *AuthFlow) Continue(ctx context.Context, in ContinueInput) error {
	return f.cont.Execute(ctx, in)
}

func (f *AuthFlow) Callback(ctx context.Context, gatewayPublicURL, state string) (*CallbackResult, error) {
	return f.callback.Execute(ctx, gatewayPublicURL, state)
}

func (f *AuthFlow) SetupMFA(ctx context.Context, state string) (*MFASetupResult, error) {
	return f.mfa.Setup(ctx, state)
}

func (f *AuthFlow) VerifyMFA(ctx context.Context, state, code string) error {
	return f.mfa.Verify(ctx, state, code)
}

func (f *AuthFlow) ExchangeCode(ctx context.Context, code, codeVerifier, clientSecret string) (*TokenResponse, error) {
	return f.exchange.Execute(ctx, code, codeVerifier, clientSecret)
}

func (f *AuthFlow) RefreshToken(ctx context.Context, refreshToken string, rc RequestCtx) (*TokenResponse, error) {
	return f.refresh.Execute(ctx, refreshToken, rc)
}

func (f *AuthFlow) Logout(ctx context.Context, token string, revokeAll bool) error {
	return f.logout.Execute(ctx, token, revokeAll)
}
