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

	httpadapter "github.com/zero-trust/zero-trust-auth/gateway/internal/adapter/http"
	redisadapter "github.com/zero-trust/zero-trust-auth/gateway/internal/adapter/redis"
	"github.com/zero-trust/zero-trust-auth/gateway/internal/cases"
	"github.com/zero-trust/zero-trust-auth/gateway/internal/transport"
	"github.com/zero-trust/zero-trust-auth/toolkit/pkg/httpserver"
	"github.com/zero-trust/zero-trust-auth/toolkit/pkg/logger"
)

func main() {
	log := logger.NewLogger("")

	redisURL := requireEnv(log, "REDIS_URL")
	clientID := requireEnv(log, "CLIENT_ID")
	clientSecret := requireEnv(log, "CLIENT_SECRET")
	trustURL := requireEnv(log, "TRUST_SERVICE_URL")
	tokenURL := requireEnv(log, "TOKEN_SERVICE_URL")
	idpURL := requireEnv(log, "IDPADAPTER_URL")
	opaURL := requireEnv(log, "OPA_URL")
	authURL := requireEnv(log, "AUTH_SERVICE_URL")
	auditURL := requireEnv(log, "AUDIT_SERVICE_URL")
	clientCallbackURL := env("CLIENT_CALLBACK_URL", "http://localhost:4000/callback")
	gatewayPublicURL := env("GATEWAY_PUBLIC_URL", "http://localhost:3000")

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

	sessions := redisadapter.NewSessionStore(redisClient)
	authcodes := redisadapter.NewAuthCodeStore(redisClient)
	trustSvc := httpadapter.NewTrustClient(trustURL)
	tokenSvc := httpadapter.NewTokenClient(tokenURL)
	idpSvc := httpadapter.NewIDPAdapterClient(idpURL)
	opaEngine := httpadapter.NewOPAClient(opaURL)
	mfaSvc := httpadapter.NewMFAClient(authURL)
	auditClient := httpadapter.NewAuditClient(auditURL)

	authorizeCase := cases.NewAuthorizeCase(sessions, trustSvc, idpSvc, clientID)
	continueCase := cases.NewContinueCase(sessions, authcodes, trustSvc)
	callbackCase := cases.NewCallbackCase(sessions, authcodes, clientCallbackURL)
	mfaCase := cases.NewMFACase(sessions, mfaSvc, continueCase, trustSvc)
	exchangeCase := cases.NewExchangeCodeCase(authcodes, tokenSvc, clientSecret)
	refreshCase := cases.NewRefreshCase(tokenSvc)
	logoutCase := cases.NewLogoutCase(tokenSvc)

	flow := cases.NewAuthFlow(authorizeCase, continueCase, callbackCase, mfaCase, exchangeCase, refreshCase, logoutCase)
	guard := cases.NewTokenGuard(tokenSvc, opaEngine, auditClient)

	h := transport.NewHandler(log, gatewayPublicURL, flow, guard)

	pub := http.NewServeMux()
	h.RegisterPublic(pub)

	priv := http.NewServeMux()
	h.RegisterPrivate(priv)

	pubSrv := httpserver.New(":3000", pub)
	privSrv := httpserver.New(":8081", priv)

	sigCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 2)
	go func() { errCh <- pubSrv.Run(sigCtx) }()
	go func() { errCh <- privSrv.Run(sigCtx) }()

	log.Info("gateway starting", "public", ":3000", "private", ":8081")
	if err := <-errCh; err != nil {
		log.Error("server failed", "error", err)
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

var _ = strings.Contains
