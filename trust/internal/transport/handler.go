package transport

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/zero-trust/zero-trust-auth/trust/internal/cases"
	"github.com/zero-trust/zero-trust-auth/trust/internal/entities"
	"github.com/zero-trust/zero-trust-auth/toolkit/pkg/metrics"
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
	mux.Handle("GET /metrics", metrics.Handler())
	mux.HandleFunc("POST /trust/anonymous-check", h.anonymousCheck)
	mux.HandleFunc("POST /trust/evaluate", h.evaluate)
	mux.HandleFunc("POST /trust/fails/incr", h.failsIncr)
	mux.HandleFunc("POST /trust/fails/reset", h.failsReset)
}

func (h *Handler) anonymousCheck(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP          string `json:"ip"`
		UserAgent   string `json:"user_agent"`
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	result, err := h.cases.AnonymousCheck(r.Context(), req.IP, req.UserAgent, req.Fingerprint)
	if err != nil {
		h.log.Error("anonymous check failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, result)
}

func (h *Handler) evaluate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID      string    `json:"user_id"`
		Roles       []string  `json:"roles"`
		IP          string    `json:"ip"`
		UserAgent   string    `json:"user_agent"`
		Fingerprint string    `json:"fingerprint"`
		Timestamp   time.Time `json:"timestamp"`
		Register    bool      `json:"register"`
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
	if req.Timestamp.IsZero() {
		req.Timestamp = time.Now().UTC()
	}
	score, err := h.cases.Evaluate(r.Context(), cases.EvaluateTrustInput{
		UserID:      userID,
		Roles:       req.Roles,
		IP:          req.IP,
		UserAgent:   req.UserAgent,
		Fingerprint: req.Fingerprint,
		Timestamp:   req.Timestamp,
		Register:    req.Register,
	})
	if err != nil {
		h.log.Error("evaluate trust failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, toEvaluateResponse(score))
}

func (h *Handler) failsIncr(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID string `json:"user_id"`
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
	if _, err := h.cases.IncrFails(r.Context(), userID); err != nil {
		h.log.Error("incr fails", "error", err)
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) failsReset(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID string `json:"user_id"`
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
	if err := h.cases.ResetFails(r.Context(), userID); err != nil {
		h.log.Error("reset fails", "error", err)
	}
	w.WriteHeader(http.StatusOK)
}

type signalResponse struct {
	Name   string  `json:"name"`
	Score  float64 `json:"score"`
	Weight float64 `json:"weight"`
}

type evaluateTrustResponse struct {
	TrustScore float64          `json:"trust_score"`
	Decision   string           `json:"decision"`
	Signals    []signalResponse `json:"signals"`
}

func toEvaluateResponse(ts *entities.TrustScore) evaluateTrustResponse {
	sigs := make([]signalResponse, len(ts.Signals))
	for i, s := range ts.Signals {
		sigs[i] = signalResponse{Name: s.Name, Score: s.Score, Weight: s.Weight}
	}
	return evaluateTrustResponse{
		TrustScore: ts.Value,
		Decision:   string(ts.Decision),
		Signals:    sigs,
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
