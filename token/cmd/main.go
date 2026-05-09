package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	rdb "github.com/redis/go-redis/v9"

	httpadapter "github.com/zero-trust/zero-trust-auth/token/internal/adapter/http"
	kafkaadapter "github.com/zero-trust/zero-trust-auth/token/internal/adapter/kafka"
	redisadapter "github.com/zero-trust/zero-trust-auth/token/internal/adapter/redis"
	"github.com/zero-trust/zero-trust-auth/token/internal/cases"
	"github.com/zero-trust/zero-trust-auth/token/internal/transport"
	"github.com/zero-trust/zero-trust-auth/toolkit/pkg/httpserver"
	"github.com/zero-trust/zero-trust-auth/toolkit/pkg/logger"
)

func main() {
	log := logger.NewLogger("")

	redisURL := requireEnv(log, "REDIS_URL")
	kafkaBrokers := requireEnv(log, "KAFKA_BROKERS")
	trustURL := requireEnv(log, "TRUST_SERVICE_URL")

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

	accessStore := redisadapter.NewAccessTokenStore(redisClient)
	refreshStore := redisadapter.NewRefreshTokenStore(redisClient)
	familyStore := redisadapter.NewTokenFamilyStore(redisClient)
	publisher := kafkaadapter.NewPublisher(kafkaBrokers)
	defer publisher.Close()
	trustClient := httpadapter.NewTrustClient(trustURL)

	issueCase := cases.NewIssueCase(accessStore, refreshStore, familyStore)
	introspectCase := cases.NewIntrospectCase(accessStore, refreshStore, familyStore, trustClient, publisher)
	refreshCase := cases.NewRefreshCase(accessStore, refreshStore, familyStore, publisher, trustClient)
	revokeCase := cases.NewRevokeCase(accessStore, refreshStore)
	adminRevokeCase := cases.NewAdminRevokeCase(familyStore, refreshStore, publisher)

	mux := http.NewServeMux()
	transport.NewHandler(log, cases.NewCases(issueCase, introspectCase, refreshCase, revokeCase, adminRevokeCase)).Register(mux)

	srv := httpserver.New(":8080", mux)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Info("token service starting", "addr", ":8080")
	if err := srv.Run(ctx); err != nil {
		log.Error("server stopped with error", "error", err)
		os.Exit(1)
	}
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
