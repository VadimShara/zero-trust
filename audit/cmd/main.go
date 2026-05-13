package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	migrate "github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"

	auditcfg "github.com/zero-trust/zero-trust-auth/audit/config"
	kafkaadapter "github.com/zero-trust/zero-trust-auth/audit/internal/adapter/kafka"
	pgadapter "github.com/zero-trust/zero-trust-auth/audit/internal/adapter/postgres"
	"github.com/zero-trust/zero-trust-auth/audit/internal/cases"
	"github.com/zero-trust/zero-trust-auth/audit/internal/transport"
	pkgconfig "github.com/zero-trust/zero-trust-auth/toolkit/pkg/config"
	"github.com/zero-trust/zero-trust-auth/toolkit/pkg/httpserver"
	"github.com/zero-trust/zero-trust-auth/toolkit/pkg/logger"
)

func main() {
	log := logger.NewLogger("")

	var cfg auditcfg.Config
	if err := pkgconfig.Load(pkgconfig.Path(), &cfg); err != nil {
		log.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	pool, err := pgxpool.New(context.Background(), cfg.Postgres.DSN)
	if err != nil {
		log.Error("postgres connect failed", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	if err := pool.Ping(context.Background()); err != nil {
		log.Error("postgres ping failed", "error", err)
		os.Exit(1)
	}

	if err := runMigrations(log, cfg.Postgres.DSN, cfg.Postgres.MigrationsPath); err != nil {
		log.Error("migrations failed", "error", err)
		os.Exit(1)
	}

	repo := pgadapter.NewAuditRepo(pool)
	handleEvent := cases.NewHandleEventCase(repo)
	queryEvents := cases.NewQueryEventsCase(repo)

	mux := http.NewServeMux()
	transport.NewHandler(log, cases.NewCases(queryEvents)).Register(mux)

	srv := httpserver.New(cfg.Server.Addr, mux)

	consumer := kafkaadapter.NewConsumer(cfg.Kafka.Brokers, cfg.Kafka.GroupID)
	defer consumer.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	messages, err := consumer.Subscribe(ctx, cfg.Kafka.Topics)
	if err != nil {
		log.Error("kafka subscribe failed", "error", err)
		os.Exit(1)
	}

	log.Info("audit service starting", "topics", cfg.Kafka.Topics, "addr", cfg.Server.Addr)

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

func runMigrations(log *slog.Logger, dsn, path string) error {
	if path == "" {
		path = "migrations"
	}
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
