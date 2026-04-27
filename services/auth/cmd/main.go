package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	migrate "github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	pgadapter "github.com/zero-trust/zero-trust-auth/services/auth/internal/adapter/postgres"
	"github.com/zero-trust/zero-trust-auth/services/auth/internal/cases"
	"github.com/zero-trust/zero-trust-auth/toolkit/pkg/httpserver"
	"github.com/zero-trust/zero-trust-auth/toolkit/pkg/logger"
)

func main() {
	log := logger.NewLogger("")

	dsn := requireEnv(log, "POSTGRES_DSN")

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

	repo := pgadapter.NewUserRepo(pool)
	resolveUser := cases.NewResolveUserCase(repo)
	mfaCase := cases.NewMFACase(repo, "ZeroTrustAuth")

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	mux.HandleFunc("POST /auth/mfa/setup", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			UserID string `json:"user_id"`
			Email  string `json:"email"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.UserID == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		result, err := mfaCase.Setup(r.Context(), req.UserID, req.Email)
		if err != nil {
			log.Error("mfa setup failed", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"secret":      result.Secret,
			"otpauth_uri": result.OTPAuthURI,
			"enrolled":    result.Enrolled,
		})
	})

	mux.HandleFunc("POST /auth/mfa/verify", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			UserID string `json:"user_id"`
			Code   string `json:"code"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.UserID == "" || req.Code == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		valid, err := mfaCase.Verify(r.Context(), req.UserID, req.Code)
		if err != nil {
			log.Error("mfa verify failed", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"valid": valid})
	})

	mux.HandleFunc("POST /auth/resolve-user", func(w http.ResponseWriter, r *http.Request) {
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

		userID, created, err := resolveUser.Execute(r.Context(), req.IDP, req.Sub, req.Email)
		if err != nil {
			log.Error("resolve user failed", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			UserID  uuid.UUID `json:"user_id"`
			Created bool      `json:"created"`
		}{UserID: userID, Created: created})
	})

	srv := httpserver.New(":8080", mux)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Info("auth service starting", "addr", ":8080")
	if err := srv.Run(ctx); err != nil {
		log.Error("server stopped with error", "error", err)
		os.Exit(1)
	}
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
