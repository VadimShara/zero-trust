package transport

import "github.com/zero-trust/zero-trust-auth/toolkit/pkg/metrics"

var (
	metricLoginTotal = metrics.NewCounter(
		"gateway_login_total",
		"OAuth login flow completions by trust decision.",
		"decision",
	)
	metricMFATotal = metrics.NewCounter(
		"gateway_mfa_total",
		"MFA (TOTP) verification attempts.",
		"result",
	)
	metricTokenExchangeTotal = metrics.NewCounter(
		"gateway_token_exchange_total",
		"Authorization code → token exchange attempts.",
		"result",
	)
	metricTokenRefreshTotal = metrics.NewCounter(
		"gateway_token_refresh_total",
		"Refresh token rotation attempts.",
		"result",
	)
	metricAPIRequestsTotal = metrics.NewCounter(
		"gateway_api_requests_total",
		"API requests through the gateway after token validation.",
		"resource", "action", "result",
	)
	metricForcedLogoutTotal = metrics.NewCounter(
		"gateway_step_up_challenges_total",
		"Number of 401 insufficient_user_authentication challenges sent to clients.",
		"resource",
	)
)
