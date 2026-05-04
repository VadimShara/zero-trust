package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	migrate "github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	rdb "github.com/redis/go-redis/v9"

	httpadapter "github.com/zero-trust/zero-trust-auth/services/trust/internal/adapter/http"
	pgadapter "github.com/zero-trust/zero-trust-auth/services/trust/internal/adapter/postgres"
	redisadapter "github.com/zero-trust/zero-trust-auth/services/trust/internal/adapter/redis"
	"github.com/zero-trust/zero-trust-auth/services/trust/internal/cases"
	"github.com/zero-trust/zero-trust-auth/services/trust/internal/entities"
	"github.com/zero-trust/zero-trust-auth/toolkit/pkg/httpserver"
	"github.com/zero-trust/zero-trust-auth/toolkit/pkg/logger"
	"github.com/zero-trust/zero-trust-auth/toolkit/pkg/metrics"
)

func main() {
	log := logger.NewLogger("")

	dsn := requireEnv(log, "POSTGRES_DSN")
	redisURL := requireEnv(log, "REDIS_URL")
	salt := os.Getenv("HASH_SALT") // SHA256 salt for IP/fingerprint hashing
	apiURL := os.Getenv("IP_REPUTATION_API_URL")
	apiKey := os.Getenv("IP_REPUTATION_API_KEY")

	// ── Postgres ─────────────────────────────────────────────────────────────
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		log.Error("postgres connect failed", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	if err := pool.Ping(context.Background()); err != nil {
		log.Error("postgres ping failed", "error", err)
		os.Exit(1)
	}

	if err := runMigrations(log, dsn); err != nil {
		log.Error("migrations failed", "error", err)
		os.Exit(1)
	}

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

	// ── Wire adapters ─────────────────────────────────────────────────────────
	trustCache := redisadapter.NewTrustCache(redisClient)
	ipRepCache := redisadapter.NewIPRepCache(redisClient)
	ipRep := httpadapter.NewIPReputationClient(ipRepCache, apiURL, apiKey, salt)
	devices := pgadapter.NewDeviceRepo(pool)
	loginHistory := pgadapter.NewLoginHistoryRepo(pool)
	workingHours := pgadapter.NewWorkingHoursRepo(pool)

	// ── Wire cases ────────────────────────────────────────────────────────────
	anonCheck := cases.NewAnonymousCheckCase(ipRep, trustCache, salt)
	evalTrust := cases.NewEvaluateTrustCase(devices, loginHistory, workingHours, trustCache, ipRep, salt)

	// ── Routes ────────────────────────────────────────────────────────────────
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.Handle("GET /metrics", metrics.Handler())

	mux.HandleFunc("POST /trust/anonymous-check", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			IP          string `json:"ip"`
			UserAgent   string `json:"user_agent"`
			Fingerprint string `json:"fingerprint"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		result, err := anonCheck.Execute(r.Context(), req.IP, req.UserAgent, req.Fingerprint)
		if err != nil {
			log.Error("anonymous check failed", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		writeJSON(w, result)
	})

	mux.HandleFunc("POST /trust/evaluate", func(w http.ResponseWriter, r *http.Request) {
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

		score, err := evalTrust.Execute(r.Context(), cases.EvaluateTrustInput{
			UserID:      userID,
			Roles:       req.Roles,
			IP:          req.IP,
			UserAgent:   req.UserAgent,
			Fingerprint: req.Fingerprint,
			Timestamp:   req.Timestamp,
			Register:    req.Register,
		})
		if err != nil {
			log.Error("evaluate trust failed", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		writeJSON(w, evaluateResponse(score))
	})

	mux.HandleFunc("POST /trust/fails/incr", func(w http.ResponseWriter, r *http.Request) {
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
		if _, err := trustCache.IncrFails(r.Context(), userID); err != nil {
			log.Error("incr fails", "error", err)
		}
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("POST /trust/fails/reset", func(w http.ResponseWriter, r *http.Request) {
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
		if err := trustCache.ResetFails(r.Context(), userID); err != nil {
			log.Error("reset fails", "error", err)
		}
		w.WriteHeader(http.StatusOK)
	})

	// ── Start ──────────────────────────────────────────────────────────────────
	srv := httpserver.New(":8080", mux)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Info("trust service starting", "addr", ":8080")
	if err := srv.Run(ctx); err != nil {
		log.Error("server stopped with error", "error", err)
		os.Exit(1)
	}
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

func evaluateResponse(ts *entities.TrustScore) evaluateTrustResponse {
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

func runMigrations(log *slog.Logger, dsn string) error {
	path := os.Getenv("MIGRATIONS_PATH")
	if path == "" {
		path = "migrations"
	}
	m, err := migrate.New("file://"+path, dsn)
	if err != nil {
		return err
	}
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return err
	}
	log.Info("migrations applied")
	return nil
}

func requireEnv(log *slog.Logger, key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Error("required env var not set", "key", key)
		os.Exit(1)
	}
	return v
}
