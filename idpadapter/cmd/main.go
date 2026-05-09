package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	rdb "github.com/redis/go-redis/v9"

	httpadapter "github.com/zero-trust/zero-trust-auth/idpadapter/internal/adapter/http"
	keycloakadapter "github.com/zero-trust/zero-trust-auth/idpadapter/internal/adapter/keycloak"
	redisadapter "github.com/zero-trust/zero-trust-auth/idpadapter/internal/adapter/redis"
	"github.com/zero-trust/zero-trust-auth/idpadapter/internal/cases"
	"github.com/zero-trust/zero-trust-auth/idpadapter/internal/transport"
	"github.com/zero-trust/zero-trust-auth/toolkit/pkg/httpserver"
	"github.com/zero-trust/zero-trust-auth/toolkit/pkg/logger"
)

func main() {
	log := logger.NewLogger("")

	keycloakIssuer := requireEnv(log, "KEYCLOAK_ISSUER")
	keycloakClientID := requireEnv(log, "KEYCLOAK_CLIENT_ID")
	keycloakClientSecret := requireEnv(log, "KEYCLOAK_CLIENT_SECRET")
	authServiceURL := requireEnv(log, "AUTH_SERVICE_URL")
	gatewayPrivateURL := requireEnv(log, "GATEWAY_PRIVATE_URL")
	redisURL := requireEnv(log, "REDIS_URL")

	gatewayPublicURL := env("GATEWAY_PUBLIC_URL", "http://gateway:3000")
	callbackURL := env("IDPADAPTER_CALLBACK_URL", "http://idpadapter:8080/idp/callback")
	keycloakPublicURL := env("KEYCLOAK_PUBLIC_URL", "")

	var oidcClient *keycloakadapter.OIDCClient
	for attempt := 1; attempt <= 30; attempt++ {
		var err error
		oidcClient, err = keycloakadapter.NewOIDCClient(
			context.Background(),
			keycloakIssuer, keycloakClientID, keycloakClientSecret, callbackURL,
			keycloakPublicURL,
		)
		if err == nil {
			break
		}
		log.Warn("keycloak not ready, retrying", "attempt", attempt, "error", err)
		if attempt == 30 {
			log.Error("oidc provider init failed after retries", "error", err)
			os.Exit(1)
		}
		time.Sleep(5 * time.Second)
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

	pkceStore := redisadapter.NewPKCEStore(redisClient)
	authClient := httpadapter.NewAuthClient(authServiceURL)
	gatewayClient := httpadapter.NewGatewayClient(gatewayPrivateURL)

	getLoginURL := cases.NewGetLoginURLCase(pkceStore, oidcClient)
	handleCallback := cases.NewHandleCallbackCase(pkceStore, oidcClient, authClient, gatewayClient, gatewayPublicURL)

	mux := http.NewServeMux()
	transport.NewHandler(log, cases.NewCases(getLoginURL, handleCallback)).Register(mux)

	srv := httpserver.New(":8080", mux)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Info("idpadapter starting", "addr", ":8080")
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

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
