package main

import "github.com/zero-trust/zero-trust-auth/toolkit/pkg/metrics"

var (
	// Login flow
	metricLoginTotal = metrics.NewCounter(
		"gateway_login_total",
		"OAuth login flow completions by trust decision.",
		"decision", // ALLOW, MFA_REQUIRED, DENY, error
	)
	metricMFATotal = metrics.NewCounter(
		"gateway_mfa_total",
		"MFA (TOTP) verification attempts.",
		"result", // success, invalid_code, not_found
	)
	metricTokenExchangeTotal = metrics.NewCounter(
		"gateway_token_exchange_total",
		"Authorization code → token exchange attempts.",
		"result", // success, invalid_grant, invalid_pkce, error
	)
	metricTokenRefreshTotal = metrics.NewCounter(
		"gateway_token_refresh_total",
		"Refresh token rotation attempts.",
		"result", // success, reuse_detected, expired, error
	)

	// API access
	metricAPIRequestsTotal = metrics.NewCounter(
		"gateway_api_requests_total",
		"API requests through the gateway after token validation.",
		"resource", "action", "result", // result: allowed, insufficient_trust, forbidden, unauthorized
	)

	// Security events
	metricForcedLogoutTotal = metrics.NewCounter(
		"gateway_step_up_challenges_total",
		"Number of 401 insufficient_user_authentication challenges sent to clients.",
		"resource",
	)
)
