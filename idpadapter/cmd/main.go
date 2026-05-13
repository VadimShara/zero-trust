package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	rdb "github.com/redis/go-redis/v9"

	idpcfg "github.com/zero-trust/zero-trust-auth/idpadapter/config"
	httpadapter "github.com/zero-trust/zero-trust-auth/idpadapter/internal/adapter/http"
	keycloakadapter "github.com/zero-trust/zero-trust-auth/idpadapter/internal/adapter/keycloak"
	redisadapter "github.com/zero-trust/zero-trust-auth/idpadapter/internal/adapter/redis"
	"github.com/zero-trust/zero-trust-auth/idpadapter/internal/cases"
	"github.com/zero-trust/zero-trust-auth/idpadapter/internal/transport"
	pkgconfig "github.com/zero-trust/zero-trust-auth/toolkit/pkg/config"
	"github.com/zero-trust/zero-trust-auth/toolkit/pkg/httpserver"
	"github.com/zero-trust/zero-trust-auth/toolkit/pkg/logger"
)

func main() {
	log := logger.NewLogger("")

	var cfg idpcfg.Config
	if err := pkgconfig.Load(pkgconfig.Path(), &cfg); err != nil {
		log.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	var oidcClient *keycloakadapter.OIDCClient
	for attempt := 1; attempt <= 30; attempt++ {
		var err error
		oidcClient, err = keycloakadapter.NewOIDCClient(
			context.Background(),
			cfg.Keycloak.Issuer, cfg.Keycloak.ClientID, cfg.Keycloak.ClientSecret, cfg.Keycloak.CallbackURL,
			cfg.Keycloak.PublicURL,
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

	pkceStore := redisadapter.NewPKCEStore(redisClient)
	authClient := httpadapter.NewAuthClient(cfg.Services.Auth)
	gatewayClient := httpadapter.NewGatewayClient(cfg.Services.GatewayPrivate)

	getLoginURL := cases.NewGetLoginURLCase(pkceStore, oidcClient)
	handleCallback := cases.NewHandleCallbackCase(pkceStore, oidcClient, authClient, gatewayClient, cfg.Services.GatewayPublic)

	mux := http.NewServeMux()
	transport.NewHandler(log, cases.NewCases(getLoginURL, handleCallback, cfg.Keycloak.Issuer, cfg.Keycloak.PublicURL, cfg.Keycloak.ClientID)).Register(mux)

	srv := httpserver.New(cfg.Server.Addr, mux)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Info("idpadapter starting", "addr", cfg.Server.Addr)
	if err := srv.Run(ctx); err != nil {
		log.Error("server stopped with error", "error", err)
		os.Exit(1)
	}
}
