package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	migrate "github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"
	rdb "github.com/redis/go-redis/v9"

	trustcfg "github.com/zero-trust/zero-trust-auth/trust/config"
	httpadapter "github.com/zero-trust/zero-trust-auth/trust/internal/adapter/http"
	pgadapter "github.com/zero-trust/zero-trust-auth/trust/internal/adapter/postgres"
	redisadapter "github.com/zero-trust/zero-trust-auth/trust/internal/adapter/redis"
	"github.com/zero-trust/zero-trust-auth/trust/internal/cases"
	"github.com/zero-trust/zero-trust-auth/trust/internal/transport"
	pkgconfig "github.com/zero-trust/zero-trust-auth/toolkit/pkg/config"
	"github.com/zero-trust/zero-trust-auth/toolkit/pkg/httpserver"
	"github.com/zero-trust/zero-trust-auth/toolkit/pkg/logger"
)

func main() {
	log := logger.NewLogger("")

	var cfg trustcfg.Config
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

	opt, err := rdb.ParseURL(cfg.Redis.URL)
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

	trustCache := redisadapter.NewTrustCache(redisClient,
		cfg.Trust.Velocity.FailTTL,
		cfg.Trust.AnonCheck.IPFailTTL,
	)
	ipRepCache := redisadapter.NewIPRepCache(redisClient)
	ipRep := httpadapter.NewIPReputationClient(ipRepCache, cfg.IPRep.APIURL, cfg.IPRep.APIKey, cfg.HashSalt)
	devices := pgadapter.NewDeviceRepo(pool)
	loginHistory := pgadapter.NewLoginHistoryRepo(pool)
	workingHours := pgadapter.NewWorkingHoursRepo(pool)

	anonCheck := cases.NewAnonymousCheckCase(ipRep, trustCache, cfg.HashSalt, cfg.Trust.AnonCheck.MaxIPFails)
	evalTrust := cases.NewEvaluateTrustCase(devices, loginHistory, workingHours, trustCache, ipRep, cfg.HashSalt, cfg.Trust)

	mux := http.NewServeMux()
	transport.NewHandler(log, cases.NewCases(anonCheck, evalTrust, trustCache)).Register(mux)

	srv := httpserver.New(cfg.Server.Addr, mux)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Info("trust service starting", "addr", cfg.Server.Addr)
	if err := srv.Run(ctx); err != nil {
		log.Error("server stopped with error", "error", err)
		os.Exit(1)
	}
}

func runMigrations(log interface{ Info(string, ...any) }, dsn, path string) error {
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
