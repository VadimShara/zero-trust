package transport

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"

	"github.com/zero-trust/zero-trust-auth/idpadapter/internal/cases"
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
	mux.HandleFunc("GET /idp/login-url", h.loginURL)
	mux.HandleFunc("GET /idp/callback", h.callback)
	mux.HandleFunc("GET /idp/logout-url", h.logoutURL)
}

func (h *Handler) logoutURL(w http.ResponseWriter, r *http.Request) {
	redirectURI := r.URL.Query().Get("post_logout_redirect_uri")
	logoutURL := h.cases.GetLogoutURL(redirectURI)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"url": logoutURL})
}

func (h *Handler) loginURL(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	if state == "" {
		http.Error(w, "state required", http.StatusBadRequest)
		return
	}
	loginURL, err := h.cases.GetLoginURL(r.Context(), state)
	if err != nil {
		h.log.Error("get login url failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"login_url": loginURL})
}

func (h *Handler) callback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		http.Error(w, "code and state required", http.StatusBadRequest)
		return
	}
	rc := cases.RequestCtx{
		IP:          remoteIP(r),
		UserAgent:   r.Header.Get("User-Agent"),
		Fingerprint: r.Header.Get("X-TLS-Fingerprint"),
	}
	redirectURL, err := h.cases.HandleCallback(r.Context(), code, state, rc)
	if err != nil {
		h.log.Error("callback failed", "error", err, "state", state)
		http.Error(w, "authentication failed", http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func remoteIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip == "" {
		return r.RemoteAddr
	}
	return ip
}
