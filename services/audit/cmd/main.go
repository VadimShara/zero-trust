package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	migrate "github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"

	kafkaadapter "github.com/zero-trust/zero-trust-auth/services/audit/internal/adapter/kafka"
	pgadapter "github.com/zero-trust/zero-trust-auth/services/audit/internal/adapter/postgres"
	"github.com/zero-trust/zero-trust-auth/services/audit/internal/cases"
	"github.com/zero-trust/zero-trust-auth/toolkit/pkg/logger"
)

var topics = []string{"auth.events", "token.events", "access.events", "admin.events"}

func main() {
	log := logger.NewLogger("")

	dsn := requireEnv(log, "POSTGRES_DSN")
	kafkaBrokers := requireEnv(log, "KAFKA_BROKERS")
	groupID := env("KAFKA_GROUP_ID", "audit-service")

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

	// ── Wire ──────────────────────────────────────────────────────────────────
	consumer := kafkaadapter.NewConsumer(strings.Split(kafkaBrokers, ","), groupID)
	defer consumer.Close()

	repo := pgadapter.NewAuditRepo(pool)
	handleEvent := cases.NewHandleEventCase(repo)

	// ── Subscribe ─────────────────────────────────────────────────────────────
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	messages, err := consumer.Subscribe(ctx, topics)
	if err != nil {
		log.Error("kafka subscribe failed", "error", err)
		os.Exit(1)
	}

	log.Info("audit service starting", "topics", topics, "group", groupID)

	// Process messages until context is cancelled and channel is closed.
	for msg := range messages {
		if err := handleEvent.Execute(ctx, msg); err != nil {
			log.Error("handle event failed",
				"topic", msg.Topic,
				"error", err,
			)
			// Continue — a single bad message must not stop the consumer.
		}
	}

	log.Info("audit service stopped")
}

func runMigrations(log *slog.Logger, dsn string) error {
	path := env("MIGRATIONS_PATH", "migrations")
	// Use a separate migrations table so audit's version counter does not
	// collide with auth's schema_migrations in the shared authdb.
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
