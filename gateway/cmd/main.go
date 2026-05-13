package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	rdb "github.com/redis/go-redis/v9"

	gatewaycfg "github.com/zero-trust/zero-trust-auth/gateway/config"
	httpadapter "github.com/zero-trust/zero-trust-auth/gateway/internal/adapter/http"
	redisadapter "github.com/zero-trust/zero-trust-auth/gateway/internal/adapter/redis"
	"github.com/zero-trust/zero-trust-auth/gateway/internal/cases"
	"github.com/zero-trust/zero-trust-auth/gateway/internal/transport"
	pkgconfig "github.com/zero-trust/zero-trust-auth/toolkit/pkg/config"
	"github.com/zero-trust/zero-trust-auth/toolkit/pkg/httpserver"
	"github.com/zero-trust/zero-trust-auth/toolkit/pkg/logger"
)

func main() {
	log := logger.NewLogger("")

	var cfg gatewaycfg.Config
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

	sessions := redisadapter.NewSessionStore(redisClient)
	authcodes := redisadapter.NewAuthCodeStore(redisClient)
	trustSvc := httpadapter.NewTrustClient(cfg.Services.Trust)
	tokenSvc := httpadapter.NewTokenClient(cfg.Services.Token)
	idpSvc := httpadapter.NewIDPAdapterClient(cfg.Services.IDPAdapter)
	opaEngine := httpadapter.NewOPAClient(cfg.Services.OPA)
	mfaSvc := httpadapter.NewMFAClient(cfg.Services.Auth)
	auditClient := httpadapter.NewAuditClient(cfg.Services.Audit)

	authorizeCase := cases.NewAuthorizeCase(sessions, trustSvc, idpSvc, cfg.Client.ID)
	continueCase := cases.NewContinueCase(sessions, authcodes, trustSvc)
	callbackCase := cases.NewCallbackCase(sessions, authcodes, cfg.Client.CallbackURL)
	mfaCase := cases.NewMFACase(sessions, mfaSvc, continueCase, trustSvc)
	exchangeCase := cases.NewExchangeCodeCase(authcodes, tokenSvc, cfg.Client.Secret)
	refreshCase := cases.NewRefreshCase(tokenSvc)
	logoutCase := cases.NewLogoutCase(tokenSvc)

	flow := cases.NewAuthFlow(authorizeCase, continueCase, callbackCase, mfaCase, exchangeCase, refreshCase, logoutCase)
	guard := cases.NewTokenGuard(tokenSvc, opaEngine, auditClient)

	h := transport.NewHandler(log, cfg.Public.GatewayURL, flow, guard, idpSvc)

	pub := http.NewServeMux()
	h.RegisterPublic(pub)

	priv := http.NewServeMux()
	h.RegisterPrivate(priv)

	pubSrv := httpserver.New(cfg.Server.PublicAddr, pub)
	privSrv := httpserver.New(cfg.Server.PrivateAddr, priv)

	sigCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 2)
	go func() { errCh <- pubSrv.Run(sigCtx) }()
	go func() { errCh <- privSrv.Run(sigCtx) }()

	log.Info("gateway starting", "public", cfg.Server.PublicAddr, "private", cfg.Server.PrivateAddr)
	if err := <-errCh; err != nil {
		log.Error("server failed", "error", err)
		os.Exit(1)
	}
}
