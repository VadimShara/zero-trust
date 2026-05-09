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
	rdb "github.com/redis/go-redis/v9"

	httpadapter "github.com/zero-trust/zero-trust-auth/trust/internal/adapter/http"
	pgadapter "github.com/zero-trust/zero-trust-auth/trust/internal/adapter/postgres"
	redisadapter "github.com/zero-trust/zero-trust-auth/trust/internal/adapter/redis"
	"github.com/zero-trust/zero-trust-auth/trust/internal/cases"
	"github.com/zero-trust/zero-trust-auth/trust/internal/transport"
	"github.com/zero-trust/zero-trust-auth/toolkit/pkg/httpserver"
	"github.com/zero-trust/zero-trust-auth/toolkit/pkg/logger"
)

func main() {
	log := logger.NewLogger("")

	dsn := requireEnv(log, "POSTGRES_DSN")
	redisURL := requireEnv(log, "REDIS_URL")
	salt := os.Getenv("HASH_SALT")
	apiURL := os.Getenv("IP_REPUTATION_API_URL")
	apiKey := os.Getenv("IP_REPUTATION_API_KEY")

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

	trustCache := redisadapter.NewTrustCache(redisClient)
	ipRepCache := redisadapter.NewIPRepCache(redisClient)
	ipRep := httpadapter.NewIPReputationClient(ipRepCache, apiURL, apiKey, salt)
	devices := pgadapter.NewDeviceRepo(pool)
	loginHistory := pgadapter.NewLoginHistoryRepo(pool)
	workingHours := pgadapter.NewWorkingHoursRepo(pool)

	anonCheck := cases.NewAnonymousCheckCase(ipRep, trustCache, salt)
	evalTrust := cases.NewEvaluateTrustCase(devices, loginHistory, workingHours, trustCache, ipRep, salt)

	mux := http.NewServeMux()
	transport.NewHandler(log, cases.NewCases(anonCheck, evalTrust, trustCache)).Register(mux)

	srv := httpserver.New(":8080", mux)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Info("trust service starting", "addr", ":8080")
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

var _ = strings.Contains
