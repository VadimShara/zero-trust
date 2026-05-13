package transport

import "github.com/zero-trust/zero-trust-auth/toolkit/pkg/metrics"

var (
	metricIntrospectTotal = metrics.NewCounter(
		"token_introspect_total",
		"Token introspect calls by result.",
		"result",
	)
	metricIssueTotal = metrics.NewCounterSimple(
		"token_issue_total",
		"Token pairs issued.",
	)
	metricRefreshTotal = metrics.NewCounter(
		"token_refresh_total",
		"Refresh token rotation attempts by result.",
		"result",
	)
	metricForcedLogoutTotal = metrics.NewCounterSimple(
		"token_forced_logout_total",
		"Sessions force-terminated due to DENY trust decision.",
	)
	metricTrustScoreHistogram = metrics.NewHistogramSimple(
		"token_introspect_trust_score",
		"Distribution of re-evaluated trust scores at introspect time.",
		metrics.TrustScoreBuckets,
	)
)
