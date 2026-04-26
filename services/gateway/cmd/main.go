package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	rdb "github.com/redis/go-redis/v9"

	httpadapter "github.com/zero-trust/zero-trust-auth/services/gateway/internal/adapter/http"
	redisadapter "github.com/zero-trust/zero-trust-auth/services/gateway/internal/adapter/redis"
	"github.com/zero-trust/zero-trust-auth/services/gateway/internal/cases"
	"github.com/zero-trust/zero-trust-auth/services/gateway/internal/port"
	pkgerrors "github.com/zero-trust/zero-trust-auth/toolkit/pkg/errors"
	"github.com/zero-trust/zero-trust-auth/toolkit/pkg/httpserver"
	"github.com/zero-trust/zero-trust-auth/toolkit/pkg/logger"
	"github.com/zero-trust/zero-trust-auth/toolkit/pkg/middleware"
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
	clientCallbackURL := env("CLIENT_CALLBACK_URL", "http://localhost:4000/callback")

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

	// ── Adapters ──────────────────────────────────────────────────────────────
	sessions := redisadapter.NewSessionStore(redisClient)
	authcodes := redisadapter.NewAuthCodeStore(redisClient)
	trustSvc := httpadapter.NewTrustClient(trustURL)
	tokenSvc := httpadapter.NewTokenClient(tokenURL)
	idpSvc := httpadapter.NewIDPAdapterClient(idpURL)
	opaEngine := httpadapter.NewOPAClient(opaURL)

	// ── Cases ─────────────────────────────────────────────────────────────────
	authorizeCase := cases.NewAuthorizeCase(sessions, trustSvc, idpSvc, clientID)
	continueCase := cases.NewContinueCase(sessions, authcodes, trustSvc)
	callbackCase := cases.NewCallbackCase(authcodes, clientCallbackURL)
	exchangeCase := cases.NewExchangeCodeCase(authcodes, tokenSvc, clientSecret)
	refreshCase := cases.NewRefreshCase(tokenSvc)
	logoutCase := cases.NewLogoutCase(tokenSvc)

	// ── Public mux (:3000) ────────────────────────────────────────────────────
	pub := http.NewServeMux()
	pub.Handle("/", middleware.Recovery()(http.NotFoundHandler()))
	pub.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	pub.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		loginURL, err := authorizeCase.Execute(r.Context(),
			q.Get("client_id"), q.Get("code_challenge"),
			q.Get("code_challenge_method"), q.Get("state"), requestCtx(r))
		if err != nil {
			if err == pkgerrors.ErrUnauthorized {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			log.Error("authorize failed", "error", err)
			http.Error(w, "bad_request", http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, loginURL, http.StatusFound)
	})

	pub.HandleFunc("GET /callback", func(w http.ResponseWriter, r *http.Request) {
		state := r.URL.Query().Get("state")
		if state == "" {
			http.Error(w, "state required", http.StatusBadRequest)
			return
		}
		redirectURL, err := callbackCase.Execute(r.Context(), state)
		if err != nil {
			log.Error("callback failed", "error", err, "state", state)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.Redirect(w, r, redirectURL, http.StatusFound)
	})

	pub.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var (
			resp    *cases.TokenResponse
			execErr error
		)
		switch r.FormValue("grant_type") {
		case "authorization_code":
			resp, execErr = exchangeCase.Execute(r.Context(),
				r.FormValue("code"), r.FormValue("code_verifier"), r.FormValue("client_secret"))
		case "refresh_token":
			resp, execErr = refreshCase.Execute(r.Context(),
				r.FormValue("refresh_token"), requestCtx(r))
		default:
			http.Error(w, "unsupported_grant_type", http.StatusBadRequest)
			return
		}
		if execErr != nil {
			switch execErr {
			case pkgerrors.ErrTokenReuse:
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "token_reuse_detected"})
			case pkgerrors.ErrNotFound, pkgerrors.ErrInvalidPKCE, pkgerrors.ErrUnauthorized:
				http.Error(w, "invalid_grant", http.StatusBadRequest)
			default:
				log.Error("token endpoint", "error", execErr)
				http.Error(w, "server_error", http.StatusInternalServerError)
			}
			return
		}
		writeJSON(w, resp)
	})

	pub.HandleFunc("POST /logout", func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if token == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var req struct {
			LogoutAll bool `json:"logout_all"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if err := logoutCase.Execute(r.Context(), token, req.LogoutAll); err != nil {
			log.Error("logout failed", "error", err)
		}
		w.WriteHeader(http.StatusOK)
	})

	pub.HandleFunc("POST /introspect", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Token string `json:"token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		active, userID, roles, score, err := tokenSvc.Introspect(r.Context(), req.Token)
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{
			"active": active, "user_id": userID, "roles": roles, "trust_score": score,
		})
	})

	// /api/* requires valid token + OPA approval
	apiHandler := apiAuthMiddleware(tokenSvc, opaEngine, log)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	pub.Handle("/api/", apiHandler)

	// ── Private mux (:8081) — internal network only ───────────────────────────
	priv := http.NewServeMux()

	priv.HandleFunc("POST /internal/continue", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			State  string          `json:"state"`
			UserID string          `json:"user_id"`
			Roles  []string        `json:"roles"`
			ReqCtx port.RequestCtx `json:"request_ctx"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if err := continueCase.Execute(r.Context(), cases.ContinueInput{
			State: req.State, UserID: req.UserID, Roles: req.Roles, ReqCtx: req.ReqCtx,
		}); err != nil {
			switch err {
			case pkgerrors.ErrTrustDenied:
				http.Error(w, "trust denied", http.StatusForbidden)
			case pkgerrors.ErrNotFound:
				http.Error(w, "session not found", http.StatusBadRequest)
			default:
				log.Error("continue failed", "error", err)
				http.Error(w, "server error", http.StatusInternalServerError)
			}
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	// ── Run both servers concurrently ─────────────────────────────────────────
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

// apiAuthMiddleware introspects the Bearer token then asks OPA for a decision.
func apiAuthMiddleware(tokens port.TokenService, policy port.PolicyEngine, log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := bearerToken(r)
			if token == "" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			active, userID, roles, score, err := tokens.Introspect(r.Context(), token)
			if err != nil || !active {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			allowed, err := policy.Allow(r.Context(), userID, roles, score,
				extractResource(r.URL.Path), methodToAction(r.Method))
			if err != nil || !allowed {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func extractResource(path string) string {
	parts := strings.SplitN(strings.TrimPrefix(path, "/api/"), "/", 2)
	if len(parts) > 0 && parts[0] != "" {
		return parts[0]
	}
	return "unknown"
}

func methodToAction(method string) string {
	if method == http.MethodGet {
		return "read"
	}
	if method == http.MethodDelete {
		return "delete"
	}
	return "write"
}

func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(auth, "Bearer ")
}

func requestCtx(r *http.Request) port.RequestCtx {
	ip := r.Header.Get("X-Real-IP")
	if ip == "" {
		ip, _, _ = net.SplitHostPort(r.RemoteAddr)
	}
	return port.RequestCtx{
		IP:        ip,
		UserAgent: r.Header.Get("User-Agent"),
		Fingerprint: r.Header.Get("X-TLS-Fingerprint"),
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
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
