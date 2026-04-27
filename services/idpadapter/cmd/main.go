package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	rdb "github.com/redis/go-redis/v9"

	httpadapter "github.com/zero-trust/zero-trust-auth/services/idpadapter/internal/adapter/http"
	keycloakadapter "github.com/zero-trust/zero-trust-auth/services/idpadapter/internal/adapter/keycloak"
	redisadapter "github.com/zero-trust/zero-trust-auth/services/idpadapter/internal/adapter/redis"
	"github.com/zero-trust/zero-trust-auth/services/idpadapter/internal/cases"
	"github.com/zero-trust/zero-trust-auth/services/idpadapter/internal/port"
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
	// Public base URL of Keycloak as seen from the user's browser.
	// Inside Docker the hostname is "keycloak"; from the host it is "localhost".
	// Set KEYCLOAK_PUBLIC_URL=http://localhost:8080 when running locally.
	keycloakPublicURL := env("KEYCLOAK_PUBLIC_URL", "")

	// ── OIDC provider ─────────────────────────────────────────────────────────
	// Retry connecting to Keycloak up to 30 times (every 5s = 150s total).
	// Keycloak takes ~30-60s to start; idpadapter must not fail before it's ready.
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

	// ── Redis ─────────────────────────────────────────────────────────────────
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

	// ── Wire ──────────────────────────────────────────────────────────────────
	pkceStore := redisadapter.NewPKCEStore(redisClient)
	authClient := httpadapter.NewAuthClient(authServiceURL)
	gatewayClient := httpadapter.NewGatewayClient(gatewayPrivateURL)

	getLoginURL := cases.NewGetLoginURLCase(pkceStore, oidcClient)
	handleCallback := cases.NewHandleCallbackCase(pkceStore, oidcClient, authClient, gatewayClient, gatewayPublicURL)

	// ── Routes ────────────────────────────────────────────────────────────────
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	// GET /idp/login-url?state=...
	// Returns: { "login_url": "https://keycloak.../..." }
	mux.HandleFunc("GET /idp/login-url", func(w http.ResponseWriter, r *http.Request) {
		state := r.URL.Query().Get("state")
		if state == "" {
			http.Error(w, "state required", http.StatusBadRequest)
			return
		}

		loginURL, err := getLoginURL.Execute(r.Context(), state)
		if err != nil {
			log.Error("get login url failed", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"login_url": loginURL})
	})

	// GET /idp/callback?code=...&state=...
	// Exchanges code → id_token, resolves user, notifies Gateway, redirects browser.
	mux.HandleFunc("GET /idp/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")
		if code == "" || state == "" {
			http.Error(w, "code and state required", http.StatusBadRequest)
			return
		}

		rc := port.RequestCtx{
			IP:          remoteIP(r),
			UserAgent:   r.Header.Get("User-Agent"),
			Fingerprint: r.Header.Get("X-TLS-Fingerprint"),
		}

		redirectURL, err := handleCallback.Execute(r.Context(), code, state, rc)
		if err != nil {
			log.Error("callback failed", "error", err, "state", state)
			http.Error(w, "authentication failed", http.StatusBadGateway)
			return
		}

		http.Redirect(w, r, redirectURL, http.StatusFound)
	})

	// ── Start ──────────────────────────────────────────────────────────────────
	srv := httpserver.New(":8080", mux)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Info("idpadapter starting", "addr", ":8080")
	if err := srv.Run(ctx); err != nil {
		log.Error("server stopped with error", "error", err)
		os.Exit(1)
	}
}

func remoteIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip == "" {
		return r.RemoteAddr
	}
	return ip
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
