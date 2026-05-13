package transport

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
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
	mux.HandleFunc("POST /auth/mfa/setup", h.mfaSetup)
	mux.HandleFunc("POST /auth/mfa/verify", h.mfaVerify)
	mux.HandleFunc("POST /auth/resolve-user", h.resolveUser)
}

func (h *Handler) mfaSetup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID string `json:"user_id"`
		Email  string `json:"email"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.UserID == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	result, err := h.cases.SetupMFA(r.Context(), req.UserID, req.Email)
	if err != nil {
		h.log.Error("mfa setup failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"secret":      result.Secret,
		"otpauth_uri": result.OTPAuthURI,
		"enrolled":    result.Enrolled,
	})
}

func (h *Handler) mfaVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID string `json:"user_id"`
		Code   string `json:"code"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.UserID == "" || req.Code == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	valid, err := h.cases.VerifyMFA(r.Context(), req.UserID, req.Code)
	if err != nil {
		h.log.Error("mfa verify failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"valid": valid})
}

func (h *Handler) resolveUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
		IDP   string `json:"idp"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	if req.Sub == "" || req.IDP == "" {
		http.Error(w, "sub and idp are required", http.StatusBadRequest)
		return
	}

	userID, created, err := h.cases.ResolveUser(r.Context(), req.IDP, req.Sub, req.Email)
	if err != nil {
		h.log.Error("resolve user failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		UserID  uuid.UUID `json:"user_id"`
		Created bool      `json:"created"`
	}{UserID: userID, Created: created})
}
