package transport

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/google/uuid"

	"github.com/zero-trust/zero-trust-auth/token/internal/cases"
	pkgerrors "github.com/zero-trust/zero-trust-auth/toolkit/pkg/errors"
	tkmetrics "github.com/zero-trust/zero-trust-auth/toolkit/pkg/metrics"
)

type Handler struct {
	log   *slog.Logger
	cases UseCases
}

func NewHandler(log *slog.Logger, cases UseCases) *Handler {
	return &Handler{log: log, cases: cases}
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.Handle("GET /metrics", tkmetrics.Handler())
	mux.HandleFunc("POST /tokens/issue", h.handleIssue)
	mux.HandleFunc("POST /tokens/introspect", h.handleIntrospect)
	mux.HandleFunc("POST /tokens/refresh", h.handleRefresh)
	mux.HandleFunc("POST /tokens/revoke", h.handleRevoke)
	mux.HandleFunc("POST /tokens/admin/revoke-user", h.handleAdminRevoke)
}

func (h *Handler) handleIssue(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID     string   `json:"user_id"`
		Roles      []string `json:"roles"`
		TrustScore float64  `json:"trust_score"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		http.Error(w, "invalid user_id", http.StatusBadRequest)
		return
	}
	atRaw, rtRaw, err := h.cases.IssueTokens(r.Context(), userID, req.Roles, req.TrustScore)
	if err != nil {
		h.log.Error("issue failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	metricIssueTotal.Inc()
	writeJSON(w, map[string]string{"access_token": atRaw, "refresh_token": rtRaw})
}

func (h *Handler) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token       string `json:"token"`
		IP          string `json:"ip"`
		UserAgent   string `json:"user_agent"`
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	tc := cases.TrustContext{IP: req.IP, UserAgent: req.UserAgent, Fingerprint: req.Fingerprint}
	result, err := h.cases.Introspect(r.Context(), req.Token, tc)
	if err != nil {
		h.log.Error("introspect failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	switch {
	case result.ForcedLogout:
		metricIntrospectTotal.WithLabelValues("forced_logout").Inc()
		metricForcedLogoutTotal.Inc()
	case result.Active:
		metricIntrospectTotal.WithLabelValues("active").Inc()
		metricTrustScoreHistogram.Observe(result.TrustScore)
	default:
		metricIntrospectTotal.WithLabelValues("inactive").Inc()
	}
	writeJSON(w, map[string]any{
		"active":      result.Active,
		"user_id":     result.UserID,
		"roles":       result.Roles,
		"trust_score": result.TrustScore,
		"exp":         result.Exp,
	})
}

func (h *Handler) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
		IP           string `json:"ip"`
		UserAgent    string `json:"user_agent"`
		Fingerprint  string `json:"fingerprint"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	tc := cases.TrustContext{IP: req.IP, UserAgent: req.UserAgent, Fingerprint: req.Fingerprint}
	atRaw, rtRaw, err := h.cases.Refresh(r.Context(), req.RefreshToken, tc)
	if err != nil {
		if err == pkgerrors.ErrTokenReuse {
			metricRefreshTotal.WithLabelValues("reuse_attack").Inc()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "token_reuse_detected"})
			return
		}
		if err == pkgerrors.ErrTokenExpired {
			metricRefreshTotal.WithLabelValues("expired").Inc()
			http.Error(w, "token expired or revoked", http.StatusUnauthorized)
			return
		}
		h.log.Error("refresh failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	metricRefreshTotal.WithLabelValues("success").Inc()
	writeJSON(w, map[string]string{"access_token": atRaw, "refresh_token": rtRaw})
}

func (h *Handler) handleRevoke(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token        string `json:"token"`
		RevokeFamily bool   `json:"revoke_family"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := h.cases.Revoke(r.Context(), req.Token, req.RevokeFamily); err != nil {
		h.log.Error("revoke failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handleAdminRevoke(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID  string `json:"user_id"`
		AdminID string `json:"admin_id"`
		Reason  string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.UserID == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		http.Error(w, "invalid user_id", http.StatusBadRequest)
		return
	}
	count, err := h.cases.AdminRevokeUser(r.Context(), userID, req.AdminID, req.Reason)
	if err != nil {
		h.log.Error("admin revoke failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"revoked_families": count, "user_id": req.UserID})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
