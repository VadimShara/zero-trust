package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/uuid"
	rdb "github.com/redis/go-redis/v9"

	httpadapter "github.com/zero-trust/zero-trust-auth/services/token/internal/adapter/http"
	kafkaadapter "github.com/zero-trust/zero-trust-auth/services/token/internal/adapter/kafka"
	redisadapter "github.com/zero-trust/zero-trust-auth/services/token/internal/adapter/redis"
	"github.com/zero-trust/zero-trust-auth/services/token/internal/cases"
	"github.com/zero-trust/zero-trust-auth/services/token/internal/port"
	pkgerrors "github.com/zero-trust/zero-trust-auth/toolkit/pkg/errors"
	"github.com/zero-trust/zero-trust-auth/toolkit/pkg/httpserver"
	"github.com/zero-trust/zero-trust-auth/toolkit/pkg/logger"
)

func main() {
	log := logger.NewLogger("")

	redisURL := requireEnv(log, "REDIS_URL")
	kafkaBrokers := requireEnv(log, "KAFKA_BROKERS")
	trustURL := requireEnv(log, "TRUST_SERVICE_URL")

	// ── Redis ─────────────────────────────────────────────────────────────────
	opt, err := rdb.ParseURL(redisURL)
	if err != nil {
		log.Error("redis url parse failed", "error", err)
		os.Exit(1)
	}
	redisClient := rdb.NewClient(opt)
	defer redisClient.Close()

	if err := redisClient.Ping(context.Background()).Err(); err != nil {
		log.Error("redis ping failed", "error", err)
		os.Exit(1)
	}

	// ── Adapters ──────────────────────────────────────────────────────────────
	accessStore := redisadapter.NewAccessTokenStore(redisClient)
	refreshStore := redisadapter.NewRefreshTokenStore(redisClient)
	familyStore := redisadapter.NewTokenFamilyStore(redisClient)
	publisher := kafkaadapter.NewPublisher(kafkaBrokers)
	defer publisher.Close()
	trustClient := httpadapter.NewTrustClient(trustURL)

	// ── Cases ─────────────────────────────────────────────────────────────────
	issueCase := cases.NewIssueCase(accessStore, refreshStore, familyStore)
	introspectCase := cases.NewIntrospectCase(accessStore, trustClient)
	refreshCase := cases.NewRefreshCase(accessStore, refreshStore, familyStore, publisher, trustClient)
	revokeCase := cases.NewRevokeCase(accessStore, refreshStore)

	// ── Routes ────────────────────────────────────────────────────────────────
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	mux.HandleFunc("POST /tokens/issue", func(w http.ResponseWriter, r *http.Request) {
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

		atRaw, rtRaw, err := issueCase.Execute(r.Context(), userID, req.Roles, req.TrustScore)
		if err != nil {
			log.Error("issue failed", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]string{"access_token": atRaw, "refresh_token": rtRaw})
	})

	mux.HandleFunc("POST /tokens/introspect", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Token     string `json:"token"`
			IP        string `json:"ip"`
			UserAgent string `json:"user_agent"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		tc := port.TrustContext{IP: req.IP, UserAgent: req.UserAgent}
		result, err := introspectCase.Execute(r.Context(), req.Token, tc)
		if err != nil {
			log.Error("introspect failed", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{
			"active":      result.Active,
			"user_id":     result.UserID,
			"roles":       result.Roles,
			"trust_score": result.TrustScore,
			"exp":         result.Exp,
		})
	})

	mux.HandleFunc("POST /tokens/refresh", func(w http.ResponseWriter, r *http.Request) {
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

		tc := port.TrustContext{IP: req.IP, UserAgent: req.UserAgent, Fingerprint: req.Fingerprint}
		atRaw, rtRaw, err := refreshCase.Execute(r.Context(), req.RefreshToken, tc)
		if err != nil {
			if err == pkgerrors.ErrTokenReuse {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "token_reuse_detected"})
				return
			}
			if err == pkgerrors.ErrTokenExpired {
				http.Error(w, "token expired or revoked", http.StatusUnauthorized)
				return
			}
			log.Error("refresh failed", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]string{"access_token": atRaw, "refresh_token": rtRaw})
	})

	mux.HandleFunc("POST /tokens/revoke", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Token        string `json:"token"`
			RevokeFamily bool   `json:"revoke_family"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		if err := revokeCase.Execute(r.Context(), req.Token, req.RevokeFamily); err != nil {
			log.Error("revoke failed", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	// ── Start ──────────────────────────────────────────────────────────────────
	srv := httpserver.New(":8080", mux)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Info("token service starting", "addr", ":8080")
	if err := srv.Run(ctx); err != nil {
		log.Error("server stopped with error", "error", err)
		os.Exit(1)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func requireEnv(log *slog.Logger, key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Error("required env var not set", "key", key)
		os.Exit(1)
	}
	return v
}
