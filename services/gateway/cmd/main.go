package main

import (
	"context"
	"encoding/json"
	"html/template"
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
	authURL := requireEnv(log, "AUTH_SERVICE_URL")
	clientCallbackURL := env("CLIENT_CALLBACK_URL", "http://localhost:4000/callback")
	gatewayPublicURL := env("GATEWAY_PUBLIC_URL", "http://localhost:3000")

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
	mfaSvc := httpadapter.NewMFAClient(authURL)

	// ── Cases ─────────────────────────────────────────────────────────────────
	authorizeCase := cases.NewAuthorizeCase(sessions, trustSvc, idpSvc, clientID)
	continueCase := cases.NewContinueCase(sessions, authcodes, trustSvc)
	callbackCase := cases.NewCallbackCase(sessions, authcodes, clientCallbackURL)
	mfaCase := cases.NewMFACase(sessions, mfaSvc, continueCase)
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
		result, err := callbackCase.Execute(r.Context(), gatewayPublicURL, state)
		if err != nil {
			log.Error("callback failed", "error", err, "state", state)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.Redirect(w, r, result.RedirectURL, http.StatusFound)
	})

	// ── MFA endpoints ─────────────────────────────────────────────────────────
	pub.HandleFunc("GET /mfa", func(w http.ResponseWriter, r *http.Request) {
		state := r.URL.Query().Get("state")
		if state == "" {
			http.Error(w, "state required", http.StatusBadRequest)
			return
		}
		setup, err := mfaCase.Setup(r.Context(), state)
		if err != nil {
			log.Error("mfa setup failed", "error", err, "state", state)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = mfaPageTmpl.Execute(w, map[string]any{
			"State":      state,
			"Secret":     setup.Secret,
			"OTPAuthURI": setup.OTPAuthURI,
			"Enrolled":   setup.Enrolled,
		})
	})

	pub.HandleFunc("POST /mfa", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		state := r.FormValue("state")
		code := r.FormValue("code")
		if state == "" || code == "" {
			http.Error(w, "state and code required", http.StatusBadRequest)
			return
		}
		if err := mfaCase.Verify(r.Context(), state, code); err != nil {
			if err == pkgerrors.ErrUnauthorized {
				// Wrong code — show form again with error message.
				setup, setupErr := mfaCase.Setup(r.Context(), state)
				if setupErr != nil {
					http.Error(w, "not found", http.StatusNotFound)
					return
				}
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusUnauthorized)
				_ = mfaPageTmpl.Execute(w, map[string]any{
					"State":      state,
					"Secret":     setup.Secret,
					"OTPAuthURI": setup.OTPAuthURI,
					"Enrolled":   setup.Enrolled,
					"Error":      "Invalid code. Please try again.",
				})
				return
			}
			log.Error("mfa verify failed", "error", err, "state", state)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		// MFA passed — redirect browser to /callback to complete the OAuth flow.
		http.Redirect(w, r, "/callback?state="+state, http.StatusFound)
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
			case pkgerrors.ErrNotFound, pkgerrors.ErrInvalidPKCE, pkgerrors.ErrUnauthorized,
				pkgerrors.ErrTokenExpired:
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
			Email  string          `json:"email"`
			Roles  []string        `json:"roles"`
			ReqCtx port.RequestCtx `json:"request_ctx"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if err := continueCase.Execute(r.Context(), cases.ContinueInput{
			State: req.State, UserID: req.UserID, Email: req.Email,
			Roles: req.Roles, ReqCtx: req.ReqCtx,
		}); err != nil {
			switch err {
			case pkgerrors.ErrTrustDenied:
				log.Error("continue: trust denied", "state", req.State, "user_id", req.UserID)
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

// mfaPageTmpl is the TOTP challenge / enrollment HTML page.
var mfaPageTmpl = template.Must(template.New("mfa").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Two-Factor Authentication</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 480px; margin: 60px auto; padding: 0 20px; color: #333; }
    h1 { font-size: 1.4rem; margin-bottom: 4px; }
    .subtitle { color: #666; margin-bottom: 24px; font-size: 0.9rem; }
    .card { background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
    .secret { font-family: monospace; font-size: 1.1rem; letter-spacing: 2px; word-break: break-all;
              background: #fff; border: 1px solid #ced4da; border-radius: 4px; padding: 10px; }
    label { display: block; font-weight: 600; margin-bottom: 6px; }
    input[type=text] { width: 100%; box-sizing: border-box; padding: 10px 12px; font-size: 1.4rem;
                       letter-spacing: 8px; text-align: center; border: 2px solid #ced4da;
                       border-radius: 6px; outline: none; }
    input[type=text]:focus { border-color: #0d6efd; }
    button { width: 100%; padding: 12px; background: #0d6efd; color: #fff; border: none;
             border-radius: 6px; font-size: 1rem; cursor: pointer; margin-top: 12px; }
    button:hover { background: #0b5ed7; }
    .error { color: #dc3545; background: #fff5f5; border: 1px solid #f5c2c7;
             border-radius: 6px; padding: 10px 14px; margin-bottom: 16px; }
    a { color: #0d6efd; }
  </style>
</head>
<body>
  <h1>Two-Factor Authentication</h1>
  <p class="subtitle">Your account requires an additional verification step.</p>

  {{if not .Enrolled}}
  <div class="card">
    <strong>First-time setup</strong>
    <p style="margin-top:8px; font-size:0.9rem;">
      Open Google Authenticator, Authy, or any TOTP app and add a new account manually using this secret key:
    </p>
    <div class="secret">{{.Secret}}</div>
    <p style="margin-top:10px; font-size:0.85rem; color:#555;">
      Or <a href="{{.OTPAuthURI}}">tap here on mobile</a> to open your authenticator app automatically.
    </p>
  </div>
  {{end}}

  {{if .Error}}
  <div class="error">{{.Error}}</div>
  {{end}}

  <form method="POST" action="/mfa">
    <input type="hidden" name="state" value="{{.State}}">
    <label for="code">Enter 6-digit code</label>
    <input type="text" id="code" name="code" maxlength="6" pattern="[0-9]{6}"
           placeholder="000000" autocomplete="one-time-code" autofocus required>
    <button type="submit">Verify</button>
  </form>
</body>
</html>
`))

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
		IP:          ip,
		UserAgent:   r.Header.Get("User-Agent"),
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
