package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	rdb "github.com/redis/go-redis/v9"

	tokencfg "github.com/zero-trust/zero-trust-auth/token/config"
	httpadapter "github.com/zero-trust/zero-trust-auth/token/internal/adapter/http"
	kafkaadapter "github.com/zero-trust/zero-trust-auth/token/internal/adapter/kafka"
	redisadapter "github.com/zero-trust/zero-trust-auth/token/internal/adapter/redis"
	"github.com/zero-trust/zero-trust-auth/token/internal/cases"
	"github.com/zero-trust/zero-trust-auth/token/internal/transport"
	pkgconfig "github.com/zero-trust/zero-trust-auth/toolkit/pkg/config"
	"github.com/zero-trust/zero-trust-auth/toolkit/pkg/httpserver"
	"github.com/zero-trust/zero-trust-auth/toolkit/pkg/logger"
)

func main() {
	log := logger.NewLogger("")

	var cfg tokencfg.Config
	if err := pkgconfig.Load(pkgconfig.Path(), &cfg); err != nil {
		log.Error("failed to load config", "error", err)
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

	accessStore := redisadapter.NewAccessTokenStore(redisClient)
	refreshStore := redisadapter.NewRefreshTokenStore(redisClient)
	familyStore := redisadapter.NewTokenFamilyStore(redisClient)
	publisher := kafkaadapter.NewPublisher(strings.Join(cfg.Kafka.Brokers, ","))
	defer publisher.Close()
	trustClient := httpadapter.NewTrustClient(cfg.Services.Trust)

	accessTTL := cfg.Tokens.AccessTTL
	refreshTTL := cfg.Tokens.RefreshTTL

	issueCase := cases.NewIssueCase(accessStore, refreshStore, familyStore, accessTTL, refreshTTL)
	introspectCase := cases.NewIntrospectCase(accessStore, refreshStore, familyStore, trustClient, publisher)
	refreshCase := cases.NewRefreshCase(accessStore, refreshStore, familyStore, publisher, trustClient, accessTTL, refreshTTL)
	revokeCase := cases.NewRevokeCase(accessStore, refreshStore)
	adminRevokeCase := cases.NewAdminRevokeCase(familyStore, refreshStore, publisher)

	mux := http.NewServeMux()
	transport.NewHandler(log, cases.NewCases(issueCase, introspectCase, refreshCase, revokeCase, adminRevokeCase)).Register(mux)

	srv := httpserver.New(cfg.Server.Addr, mux)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Info("token service starting", "addr", cfg.Server.Addr)
	if err := srv.Run(ctx); err != nil {
		log.Error("server stopped with error", "error", err)
		os.Exit(1)
	}
}
