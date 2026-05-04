package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	migrate "github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"

	kafkaadapter "github.com/zero-trust/zero-trust-auth/services/audit/internal/adapter/kafka"
	pgadapter "github.com/zero-trust/zero-trust-auth/services/audit/internal/adapter/postgres"
	"github.com/zero-trust/zero-trust-auth/services/audit/internal/cases"
	"github.com/zero-trust/zero-trust-auth/services/audit/internal/port"
	"github.com/zero-trust/zero-trust-auth/toolkit/pkg/httpserver"
	"github.com/zero-trust/zero-trust-auth/toolkit/pkg/logger"
)

var topics = []string{"auth.events", "token.events", "access.events", "admin.events"}

func main() {
	log := logger.NewLogger("")

	dsn := requireEnv(log, "POSTGRES_DSN")
	kafkaBrokers := requireEnv(log, "KAFKA_BROKERS")
	groupID := env("KAFKA_GROUP_ID", "audit-service")

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

	repo := pgadapter.NewAuditRepo(pool)
	handleEvent := cases.NewHandleEventCase(repo)
	queryEvents := cases.NewQueryEventsCase(repo)

	// ── HTTP server ───────────────────────────────────────────────────────────
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("GET /audit/events", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		limit, _ := strconv.Atoi(q.Get("limit"))
		offset, _ := strconv.Atoi(q.Get("offset"))

		f := port.QueryFilter{
			UserID:    q.Get("user_id"),
			EventType: q.Get("event_type"),
			From:      q.Get("from"),
			To:        q.Get("to"),
			Limit:     limit,
			Offset:    offset,
		}

		events, total, err := queryEvents.Execute(r.Context(), f)
		if err != nil {
			log.Error("query events failed", "error", err)
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
	})

	srv := httpserver.New(":8080", mux)

	// ── Kafka consumer + HTTP — run concurrently ──────────────────────────────
	consumer := kafkaadapter.NewConsumer(strings.Split(kafkaBrokers, ","), groupID)
	defer consumer.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	messages, err := consumer.Subscribe(ctx, topics)
	if err != nil {
		log.Error("kafka subscribe failed", "error", err)
		os.Exit(1)
	}

	log.Info("audit service starting", "topics", topics, "addr", ":8080")

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Run(ctx) }()

	go func() {
		for msg := range messages {
			if err := handleEvent.Execute(ctx, msg); err != nil {
				log.Error("handle event failed", "topic", msg.Topic, "error", err)
			}
		}
	}()

	select {
	case err := <-errCh:
		if err != nil {
			log.Error("http server failed", "error", err)
		}
	case <-ctx.Done():
	}

	log.Info("audit service stopped")
}

func runMigrations(log *slog.Logger, dsn string) error {
	path := env("MIGRATIONS_PATH", "migrations")
	sep := "&"
	if !strings.Contains(dsn, "?") {
		sep = "?"
	}
	dsnWithTable := dsn + sep + "x-migrations-table=audit_schema_migrations"
	m, err := migrate.New("file://"+path, dsnWithTable)
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

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
