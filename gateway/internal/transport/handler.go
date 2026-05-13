package transport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/zero-trust/zero-trust-auth/gateway/internal/cases"
	pkgerrors "github.com/zero-trust/zero-trust-auth/toolkit/pkg/errors"
	"github.com/zero-trust/zero-trust-auth/toolkit/pkg/metrics"
	"github.com/zero-trust/zero-trust-auth/toolkit/pkg/middleware"
)

type Handler struct {
	log              *slog.Logger
	gatewayPublicURL string
	flow             authFlow
	guard            tokenGuard
	idp              idpLogoutProvider
}

type idpLogoutProvider interface {
	GetLogoutURL(ctx context.Context, postLogoutRedirectURI string) (string, error)
}

func NewHandler(log *slog.Logger, gatewayPublicURL string, flow authFlow, guard tokenGuard, idp idpLogoutProvider) *Handler {
	return &Handler{
		log:              log,
		gatewayPublicURL: gatewayPublicURL,
		flow:             flow,
		guard:            guard,
		idp:              idp,
	}
}

func (h *Handler) RegisterPublic(mux *http.ServeMux) {
	mux.Handle("/", middleware.Recovery()(http.NotFoundHandler()))
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.Handle("GET /metrics", metrics.Handler())

	mux.HandleFunc("GET /authorize", h.authorize)
	mux.HandleFunc("GET /callback", h.callback)
	mux.HandleFunc("GET /sso-logout", h.ssoLogout)
	mux.HandleFunc("GET /mfa", h.mfaGet)
	mux.HandleFunc("POST /mfa", h.mfaPost)
	mux.HandleFunc("POST /token", h.token)
	mux.HandleFunc("POST /logout", h.logout)
	mux.HandleFunc("POST /introspect", h.introspect)

	mux.Handle("/api/", h.apiAuthMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	mux.Handle("POST /admin/users/{id}/revoke", h.apiAuthMiddleware()(http.HandlerFunc(h.adminRevoke)))
	mux.Handle("GET /audit/events", h.apiAuthMiddleware()(http.HandlerFunc(h.auditEvents)))
}

func (h *Handler) RegisterPrivate(mux *http.ServeMux) {
	mux.HandleFunc("POST /internal/continue", h.internalContinue)
}

func (h *Handler) ssoLogout(w http.ResponseWriter, r *http.Request) {
	postLogout := r.URL.Query().Get("redirect_uri")
	if postLogout == "" {
		postLogout = h.gatewayPublicURL
	}
	logoutURL, err := h.idp.GetLogoutURL(r.Context(), postLogout)
	if err != nil {
		http.Error(w, "logout unavailable", http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, logoutURL, http.StatusFound)
}

func (h *Handler) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	loginURL, err := h.flow.Authorize(r.Context(),
		q.Get("client_id"), q.Get("code_challenge"),
		q.Get("code_challenge_method"), q.Get("state"), requestCtx(r))
	if err != nil {
		if err == pkgerrors.ErrUnauthorized {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h.log.Error("authorize failed", "error", err)
		http.Error(w, "bad_request", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, loginURL, http.StatusFound)
}

func (h *Handler) callback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	if state == "" {
		http.Error(w, "state required", http.StatusBadRequest)
		return
	}
	result, err := h.flow.Callback(r.Context(), h.gatewayPublicURL, state)
	if err != nil {
		h.log.Error("callback failed", "error", err, "state", state)
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	http.Redirect(w, r, result.RedirectURL, http.StatusFound)
}

func (h *Handler) mfaGet(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	if state == "" {
		http.Error(w, "state required", http.StatusBadRequest)
		return
	}
	setup, err := h.flow.SetupMFA(r.Context(), state)
	if err != nil {
		h.log.Error("mfa setup failed", "error", err, "state", state)
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = mfaPageTmpl.Execute(w, map[string]any{
		"State":      state,
		"Secret":     setup.Secret,
		"OTPAuthURI": setup.OTPAuthURI,
		"Enrolled":   setup.Enrolled,
	})
}

func (h *Handler) mfaPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	state := r.FormValue("state")
	code := r.FormValue("code")
	if state == "" || code == "" {
		http.Error(w, "state and code required", http.StatusBadRequest)
		return
	}
	if err := h.flow.VerifyMFA(r.Context(), state, code); err != nil {
		if err == pkgerrors.ErrUnauthorized {
			metricMFATotal.WithLabelValues("invalid_code").Inc()
			setup, setupErr := h.flow.SetupMFA(r.Context(), state)
			if setupErr != nil {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			_ = mfaPageTmpl.Execute(w, map[string]any{
				"State":      state,
				"Secret":     setup.Secret,
				"OTPAuthURI": setup.OTPAuthURI,
				"Enrolled":   setup.Enrolled,
				"Error":      "Invalid code. Please try again.",
			})
			return
		}
		h.log.Error("mfa verify failed", "error", err, "state", state)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	metricMFATotal.WithLabelValues("success").Inc()
	http.Redirect(w, r, "/callback?state="+state, http.StatusFound)
}

func (h *Handler) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var (
		resp    *cases.TokenResponse
		execErr error
	)
	switch r.FormValue("grant_type") {
	case "authorization_code":
		resp, execErr = h.flow.ExchangeCode(r.Context(),
			r.FormValue("code"), r.FormValue("code_verifier"), r.FormValue("client_secret"))
	case "refresh_token":
		resp, execErr = h.flow.RefreshToken(r.Context(),
			r.FormValue("refresh_token"), requestCtx(r))
	default:
		http.Error(w, "unsupported_grant_type", http.StatusBadRequest)
		return
	}
	if execErr != nil {
		switch execErr {
		case pkgerrors.ErrTokenReuse:
			metricTokenRefreshTotal.WithLabelValues("reuse_detected").Inc()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "token_reuse_detected"})
		case pkgerrors.ErrNotFound, pkgerrors.ErrInvalidPKCE, pkgerrors.ErrUnauthorized,
			pkgerrors.ErrTokenExpired:
			if r.FormValue("grant_type") == "authorization_code" {
				metricTokenExchangeTotal.WithLabelValues("invalid_grant").Inc()
			} else {
				metricTokenRefreshTotal.WithLabelValues("expired").Inc()
			}
			http.Error(w, "invalid_grant", http.StatusBadRequest)
		default:
			h.log.Error("token endpoint", "error", execErr)
			http.Error(w, "server_error", http.StatusInternalServerError)
		}
		return
	}
	if r.FormValue("grant_type") == "authorization_code" {
		metricTokenExchangeTotal.WithLabelValues("success").Inc()
	} else {
		metricTokenRefreshTotal.WithLabelValues("success").Inc()
	}
	writeJSON(w, resp)
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if token == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		LogoutAll bool `json:"logout_all"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if err := h.flow.Logout(r.Context(), token, req.LogoutAll); err != nil {
		h.log.Error("logout failed", "error", err)
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) introspect(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	active, userID, roles, score, signals, err := h.guard.Introspect(r.Context(), req.Token, requestCtx(r))
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{
		"active": active, "user_id": userID, "roles": roles, "trust_score": score, "login_signals": signals,
	})
}

func (h *Handler) adminRevoke(w http.ResponseWriter, r *http.Request) {
	adminToken := bearerToken(r)
	_, adminID, _, _, _, _ := h.guard.Introspect(r.Context(), adminToken, requestCtx(r))

	targetUserID := r.PathValue("id")
	if targetUserID == "" {
		http.Error(w, "user_id required", http.StatusBadRequest)
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Reason == "" {
		body.Reason = "admin_initiated"
	}
	count, err := h.guard.AdminRevokeUser(r.Context(), targetUserID, adminID, body.Reason)
	if err != nil {
		h.log.Error("admin revoke failed", "error", err, "target", targetUserID)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	h.log.Info("admin revoked user tokens",
		"target_user", targetUserID, "admin", adminID, "families", count)
	writeJSON(w, map[string]any{"revoked_families": count, "user_id": targetUserID})
}

func (h *Handler) auditEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	params := map[string]string{
		"user_id":    q.Get("user_id"),
		"event_type": q.Get("event_type"),
		"from":       q.Get("from"),
		"to":         q.Get("to"),
		"limit":      q.Get("limit"),
		"offset":     q.Get("offset"),
	}
	result, err := h.guard.QueryAudit(r.Context(), params)
	if err != nil {
		h.log.Error("audit query failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, result)
}

func (h *Handler) internalContinue(w http.ResponseWriter, r *http.Request) {
	var req struct {
		State  string           `json:"state"`
		UserID string           `json:"user_id"`
		Email  string           `json:"email"`
		Roles  []string         `json:"roles"`
		ReqCtx cases.RequestCtx `json:"request_ctx"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := h.flow.Continue(r.Context(), cases.ContinueInput{
		State: req.State, UserID: req.UserID, Email: req.Email,
		Roles: req.Roles, ReqCtx: req.ReqCtx,
	}); err != nil {
		switch err {
		case pkgerrors.ErrTrustDenied:
			metricLoginTotal.WithLabelValues("DENY").Inc()
			h.log.Error("continue: trust denied", "state", req.State, "user_id", req.UserID)
			http.Error(w, "trust denied", http.StatusForbidden)
		case pkgerrors.ErrNotFound:
			http.Error(w, "session not found", http.StatusBadRequest)
		default:
			metricLoginTotal.WithLabelValues("error").Inc()
			h.log.Error("continue failed", "error", err)
			http.Error(w, "server error", http.StatusInternalServerError)
		}
		return
	}
	metricLoginTotal.WithLabelValues("success").Inc()
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) apiAuthMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := bearerToken(r)
			if token == "" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			active, userID, roles, score, _, err := h.guard.Introspect(r.Context(), token, requestCtx(r))
			if err != nil || !active {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			resource := extractResource(r.URL.Path)
			action := methodToAction(r.Method)
			decision, err := h.guard.Decide(r.Context(), userID, roles, score, resource, action)
			if err != nil {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			if !decision.Allow {
				if decision.DenyReason == "insufficient_trust" {
					metricForcedLogoutTotal.WithLabelValues(resource).Inc()
					metricAPIRequestsTotal.WithLabelValues(resource, action, "insufficient_trust").Inc()
					challenge := `Bearer error="insufficient_user_authentication",` +
						`error_description="Trust score too low. Re-authenticate to step up.",` +
						`acr_values="zero_trust_mfa",` +
						`authorization_uri="` + h.gatewayPublicURL + `/authorize"`
					w.Header().Set("WWW-Authenticate", challenge)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnauthorized)
					_ = json.NewEncoder(w).Encode(map[string]string{
						"error":             "insufficient_user_authentication",
						"error_description": "Trust score too low. Re-authenticate to step up.",
						"acr_values":        "zero_trust_mfa",
						"authorization_uri": h.gatewayPublicURL + "/authorize",
					})
					return
				}
				metricAPIRequestsTotal.WithLabelValues(resource, action, "forbidden").Inc()
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			metricAPIRequestsTotal.WithLabelValues(resource, action, "allowed").Inc()
			next.ServeHTTP(w, r)
		})
	}
}

var gwIPCache struct {
	sync.Mutex
	ip         string
	resolvedAt time.Time
}

const gwIPCacheTTL = 10 * time.Second

var gwHTTPClient = &http.Client{Timeout: 3 * time.Second}

func resolvePublicIP() string {
	gwIPCache.Lock()
	defer gwIPCache.Unlock()
	if gwIPCache.ip != "" && time.Since(gwIPCache.resolvedAt) < gwIPCacheTTL {
		return gwIPCache.ip
	}
	for _, endpoint := range []string{"https://api.ipify.org", "https://ifconfig.me/ip"} {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			cancel()
			continue
		}
		resp, err := gwHTTPClient.Do(req)
		cancel()
		if err != nil || resp.StatusCode != http.StatusOK {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 64))
		resp.Body.Close()
		if err != nil {
			continue
		}
		ip := strings.TrimSpace(string(b))
		if net.ParseIP(ip) != nil && !isPrivateIP(ip) {
			gwIPCache.ip = ip
			gwIPCache.resolvedAt = time.Now()
			return ip
		}
	}
	return gwIPCache.ip
}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true
	}
	for _, cidr := range []string{
		"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12",
		"192.168.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
	} {
		_, block, _ := net.ParseCIDR(cidr)
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

func requestCtx(r *http.Request) cases.RequestCtx {
	ip := r.Header.Get("X-Real-IP")
	if ip == "" {
		ip, _, _ = net.SplitHostPort(r.RemoteAddr)
	}
	if isPrivateIP(ip) {
		if pub := resolvePublicIP(); pub != "" {
			ip = pub
		}
	}
	fp := r.Header.Get("X-TLS-Fingerprint")
	if fp == "" {
		fp = softFingerprint(r)
	}
	return cases.RequestCtx{
		IP:          ip,
		UserAgent:   r.Header.Get("User-Agent"),
		Fingerprint: fp,
	}
}

func softFingerprint(r *http.Request) string {
	h := sha256.New()
	for _, hdr := range []string{
		r.Header.Get("User-Agent"),
		r.Header.Get("Accept-Language"),
		r.Header.Get("Accept-Encoding"),
	} {
		h.Write([]byte(hdr + "|"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func extractResource(path string) string {
	if rest, ok := strings.CutPrefix(path, "/api/"); ok {
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) > 0 && parts[0] != "" {
			return parts[0]
		}
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) > 0 && parts[0] != "" {
		return parts[0]
	}
	return "unknown"
}

func methodToAction(method string) string {
	if method == http.MethodGet {
		return "read"
	}
	if method == http.MethodDelete {
		return "delete"
	}
	return "write"
}

func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(auth, "Bearer ")
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

var mfaPageTmpl = template.Must(template.New("mfa").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Two-Factor Authentication</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 480px; margin: 60px auto; padding: 0 20px; color: #333; }
    h1 { font-size: 1.4rem; margin-bottom: 4px; }
    .subtitle { color: #666; margin-bottom: 24px; font-size: 0.9rem; }
    .card { background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
    .secret { font-family: monospace; font-size: 1.1rem; letter-spacing: 2px; word-break: break-all;
              background: #fff; border: 1px solid #ced4da; border-radius: 4px; padding: 10px; }
    label { display: block; font-weight: 600; margin-bottom: 6px; }
    input[type=text] { width: 100%; box-sizing: border-box; padding: 10px 12px; font-size: 1.4rem;
                       letter-spacing: 8px; text-align: center; border: 2px solid #ced4da;
                       border-radius: 6px; outline: none; }
    input[type=text]:focus { border-color: #0d6efd; }
    button { width: 100%; padding: 12px; background: #0d6efd; color: #fff; border: none;
             border-radius: 6px; font-size: 1rem; cursor: pointer; margin-top: 12px; }
    button:hover { background: #0b5ed7; }
    .error { color: #dc3545; background: #fff5f5; border: 1px solid #f5c2c7;
             border-radius: 6px; padding: 10px 14px; margin-bottom: 16px; }
    a { color: #0d6efd; }
  </style>
</head>
<body>
  <h1>Two-Factor Authentication</h1>
  <p class="subtitle">Your account requires an additional verification step.</p>

  {{if not .Enrolled}}
  <div class="card">
    <strong>First-time setup</strong>
    <p style="margin-top:8px; font-size:0.9rem;">
      Open Google Authenticator, Authy, or any TOTP app and add a new account manually using this secret key:
    </p>
    <div class="secret">{{.Secret}}</div>
    <p style="margin-top:10px; font-size:0.85rem; color:#555;">
      Or <a href="{{.OTPAuthURI}}">tap here on mobile</a> to open your authenticator app automatically.
    </p>
  </div>
  {{end}}

  {{if .Error}}
  <div class="error">{{.Error}}</div>
  {{end}}

  <form method="POST" action="/mfa">
    <input type="hidden" name="state" value="{{.State}}">
    <label for="code">Enter 6-digit code</label>
    <input type="text" id="code" name="code" maxlength="6" pattern="[0-9]{6}"
           placeholder="000000" autocomplete="one-time-code" autofocus required>
    <button type="submit">Verify</button>
  </form>
</body>
</html>
`))
