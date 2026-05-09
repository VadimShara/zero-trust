package transport

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/zero-trust/zero-trust-auth/audit/internal/cases"
)

type Handler struct {
	log   *slog.Logger
	cases UseCases
}

func NewHandler(log *slog.Logger, cases UseCases) *Handler {
	return &Handler{log: log, cases: cases}
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /audit/events", h.handleQueryEvents)
}

func (h *Handler) handleQueryEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))

	f := cases.QueryFilter{
		UserID:    q.Get("user_id"),
		EventType: q.Get("event_type"),
		From:      q.Get("from"),
		To:        q.Get("to"),
		Limit:     limit,
		Offset:    offset,
	}

	events, total, err := h.cases.QueryEvents(r.Context(), f)
	if err != nil {
		h.log.Error("query events failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	type eventDTO struct {
		ID        string         `json:"id"`
		EventType string         `json:"event_type"`
		UserID    *string        `json:"user_id,omitempty"`
		Payload   map[string]any `json:"payload"`
		CreatedAt string         `json:"created_at"`
	}

	dtos := make([]eventDTO, 0, len(events))
	for _, e := range events {
		dto := eventDTO{
			ID:        e.ID.String(),
			EventType: e.EventType,
			Payload:   e.Payload,
			CreatedAt: e.CreatedAt.Format("2006-01-02T15:04:05Z"),
		}
		if e.UserID != nil {
			s := e.UserID.String()
			dto.UserID = &s
		}
		dtos = append(dtos, dto)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"events": dtos,
		"total":  total,
		"limit":  f.Limit,
		"offset": f.Offset,
	})
}
