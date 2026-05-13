package gateway_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	rdb "github.com/redis/go-redis/v9"

	httpadapter "github.com/zero-trust/zero-trust-auth/gateway/internal/adapter/http"
	redisadapter "github.com/zero-trust/zero-trust-auth/gateway/internal/adapter/redis"
	"github.com/zero-trust/zero-trust-auth/gateway/internal/cases"
	pkgerrors "github.com/zero-trust/zero-trust-auth/toolkit/pkg/errors"
)

func testWriteJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

var noFollow = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func testExtractResource(path string) string {
	trimmed := strings.TrimPrefix(path, "/api/")
	if i := strings.IndexByte(trimmed, '/'); i >= 0 {
		trimmed = trimmed[:i]
	}
	if trimmed == "" {
		return "unknown"
	}
	return trimmed
}

func testMethodToAction(method string) string {
	if method == http.MethodGet {
		return "read"
	}
	if method == http.MethodDelete {
		return "delete"
	}
	return "write"
}

func testBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(auth, "Bearer ")
}

func mockKeycloak(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/realms/demo/protocol/openid-connect/auth":
			fmt.Fprintf(w, "keycloak login form")
		case "/realms/demo/protocol/openid-connect/token":
			testWriteJSON(w, map[string]string{"id_token": "fake.jwt.token"})
		case "/realms/demo/protocol/openid-connect/certs":
			testWriteJSON(w, map[string]any{"keys": []any{}})
		default:
			http.NotFound(w, r)
		}
	}))
}

func mockTrust(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/trust/anonymous-check":
			testWriteJSON(w, map[string]string{"decision": "ALLOW", "reason": ""})
		case "/trust/evaluate":
			testWriteJSON(w, map[string]any{
				"trust_score": 0.91,
				"decision":    "ALLOW",
				"signals":     []any{},
			})
		default:
			t.Errorf("mockTrust: unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
}

func mockToken(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/tokens/issue":
			testWriteJSON(w, map[string]string{
				"access_token":  "opaque-access",
				"refresh_token": "opaque-refresh",
			})
		case "/tokens/introspect":
			testWriteJSON(w, map[string]any{
				"active":      true,
				"user_id":     "usr-123",
				"roles":       []string{"developer"},
				"trust_score": 0.91,
			})
		case "/tokens/revoke":
			w.WriteHeader(http.StatusOK)
		case "/tokens/refresh":
			testWriteJSON(w, map[string]string{
				"access_token":  "opaque-access-new",
				"refresh_token": "opaque-refresh-new",
			})
		default:
			t.Errorf("mockToken: unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
}

func mockAuth(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/resolve-user" {
			testWriteJSON(w, map[string]any{"user_id": "usr-123", "created": false})
			return
		}
		http.NotFound(w, r)
	}))
}

func mockIDPAdapter(t *testing.T, keycloakURL string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/idp/login-url" {
			state := r.URL.Query().Get("state")
			loginURL := fmt.Sprintf("%s/realms/demo/protocol/openid-connect/auth?state=%s", keycloakURL, state)
			testWriteJSON(w, map[string]string{"login_url": loginURL})
			return
		}
		http.NotFound(w, r)
	}))
}

func mockOPA(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/data/authz/allow" {
			http.NotFound(w, r)
			return
		}
		var req struct {
			Input struct {
				Resource string `json:"resource"`
			} `json:"input"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		allow := req.Input.Resource != "secrets"
		testWriteJSON(w, map[string]bool{"result": allow})
	}))
}

func TestFullLoginFlow(t *testing.T) {
	keycloak := mockKeycloak(t)
	defer keycloak.Close()

	trust := mockTrust(t)
	defer trust.Close()

	token := mockToken(t)
	defer token.Close()

	auth := mockAuth(t)
	defer auth.Close()

	idp := mockIDPAdapter(t, keycloak.URL)
	defer idp.Close()

	opa := mockOPA(t)
	defer opa.Close()

	mini, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mini.Close()

	redisClient := rdb.NewClient(&rdb.Options{Addr: mini.Addr()})
	defer redisClient.Close()

	sessions := redisadapter.NewSessionStore(redisClient)
	authcodes := redisadapter.NewAuthCodeStore(redisClient)
	trustSvc := httpadapter.NewTrustClient(trust.URL)
	tokenSvc := httpadapter.NewTokenClient(token.URL)
	idpSvc := httpadapter.NewIDPAdapterClient(idp.URL)
	opaEngine := httpadapter.NewOPAClient(opa.URL)

	const (
		clientID          = "test"
		clientSecret      = "test-secret"
		clientCallbackURL = "http://test-client.example.com/callback"
	)

	authorizeCase := cases.NewAuthorizeCase(sessions, trustSvc, idpSvc, clientID)
	continueCase := cases.NewContinueCase(sessions, authcodes, trustSvc)
	callbackCase := cases.NewCallbackCase(sessions, authcodes, clientCallbackURL)
	exchangeCase := cases.NewExchangeCodeCase(authcodes, tokenSvc, clientSecret)
	refreshCase := cases.NewRefreshCase(tokenSvc)
	logoutCase := cases.NewLogoutCase(tokenSvc)

	apiAuth := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tkn := testBearerToken(r)
			if tkn == "" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			active, userID, roles, score, _, err := tokenSvc.Introspect(r.Context(), tkn, cases.RequestCtx{
				IP:          r.Header.Get("X-Real-IP"),
				UserAgent:   r.Header.Get("User-Agent"),
				Fingerprint: r.Header.Get("X-TLS-Fingerprint"),
			})
			if err != nil || !active {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			decision, err := opaEngine.Decide(r.Context(), userID, roles, score,
				testExtractResource(r.URL.Path), testMethodToAction(r.Method))
			if err != nil || decision == nil || !decision.Allow {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}

	pub := http.NewServeMux()

	pub.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		rc := cases.RequestCtx{
			IP:        r.Header.Get("X-Real-IP"),
			UserAgent: r.Header.Get("User-Agent"),
		}
		loginURL, err := authorizeCase.Execute(r.Context(),
			q.Get("client_id"), q.Get("code_challenge"),
			q.Get("code_challenge_method"), q.Get("state"), rc)
		if err != nil {
			if err == pkgerrors.ErrUnauthorized {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, loginURL, http.StatusFound)
	})

	pub.HandleFunc("GET /callback", func(w http.ResponseWriter, r *http.Request) {
		state := r.URL.Query().Get("state")
		result, err := callbackCase.Execute(r.Context(), "http://localhost:3000", state)
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.Redirect(w, r, result.RedirectURL, http.StatusFound)
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
			rc := cases.RequestCtx{IP: r.Header.Get("X-Real-IP")}
			resp, execErr = refreshCase.Execute(r.Context(), r.FormValue("refresh_token"), rc)
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
				http.Error(w, "server_error", http.StatusInternalServerError)
			}
			return
		}
		testWriteJSON(w, resp)
	})

	pub.HandleFunc("POST /logout", func(w http.ResponseWriter, r *http.Request) {
		tkn := testBearerToken(r)
		if tkn == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var req struct {
			LogoutAll bool `json:"logout_all"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		_ = logoutCase.Execute(r.Context(), tkn, req.LogoutAll)
		w.WriteHeader(http.StatusOK)
	})

	pub.Handle("/api/", apiAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	priv := http.NewServeMux()

	priv.HandleFunc("POST /internal/continue", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			State  string          `json:"state"`
			UserID string          `json:"user_id"`
			Roles  []string        `json:"roles"`
			ReqCtx cases.RequestCtx `json:"request_ctx"`
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
				http.Error(w, "server error", http.StatusInternalServerError)
			}
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	pubSrv := httptest.NewServer(pub)
	defer pubSrv.Close()

	privSrv := httptest.NewServer(priv)
	defer privSrv.Close()

	t.Logf("gateway public:  %s", pubSrv.URL)
	t.Logf("gateway private: %s", privSrv.URL)

	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h[:])

	t.Log("Step 1: GET /authorize")
	authorizeURL := fmt.Sprintf(
		"%s/authorize?client_id=%s&code_challenge=%s&code_challenge_method=S256&state=test-state&response_type=code",
		pubSrv.URL, clientID, url.QueryEscape(codeChallenge),
	)
	resp, err := noFollow.Get(authorizeURL)
	if err != nil {
		t.Fatalf("Step 1 request failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("Step 1 FAIL: want 302, got %d", resp.StatusCode)
	}
	loc1 := resp.Header.Get("Location")
	if !strings.Contains(loc1, "openid-connect/auth") {
		t.Fatalf("Step 1 FAIL: location %q does not contain Keycloak auth endpoint", loc1)
	}
	t.Logf("Step 1 OK → redirect to %s", loc1)

	t.Log("Step 2: POST /internal/continue")
	continueBody, _ := json.Marshal(map[string]any{
		"state":   "test-state",
		"user_id": "usr-123",
		"roles":   []string{"developer"},
		"request_ctx": map[string]string{
			"ip": "1.2.3.4", "user_agent": "test-browser", "fingerprint": "",
		},
	})
	resp, err = http.Post(privSrv.URL+"/internal/continue", "application/json", bytes.NewReader(continueBody))
	if err != nil {
		t.Fatalf("Step 2 request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Step 2 FAIL: want 200, got %d", resp.StatusCode)
	}
	t.Log("Step 2 OK → own_code generated and stored")

	t.Log("Step 3: GET /callback?state=test-state")
	resp, err = noFollow.Get(pubSrv.URL + "/callback?state=test-state")
	if err != nil {
		t.Fatalf("Step 3 request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("Step 3 FAIL: want 302, got %d", resp.StatusCode)
	}

	loc3 := resp.Header.Get("Location")
	parsed, err := url.Parse(loc3)
	if err != nil {
		t.Fatalf("Step 3 FAIL: cannot parse location %q: %v", loc3, err)
	}
	ownCode := parsed.Query().Get("code")
	if ownCode == "" {
		t.Fatalf("Step 3 FAIL: no code in redirect location %q", loc3)
	}
	if got := parsed.Query().Get("state"); got != "test-state" {
		t.Fatalf("Step 3 FAIL: want state=test-state, got %q", got)
	}
	t.Logf("Step 3 OK → own_code=%s…%s state=test-state", ownCode[:4], ownCode[len(ownCode)-4:])

	t.Log("Step 4: POST /token (authorization_code)")
	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "authorization_code")
	tokenForm.Set("code", ownCode)
	tokenForm.Set("code_verifier", codeVerifier)
	tokenForm.Set("client_secret", clientSecret)

	resp, err = http.PostForm(pubSrv.URL+"/token", tokenForm)
	if err != nil {
		t.Fatalf("Step 4 request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Step 4 FAIL: want 200, got %d — %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var tokenResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("Step 4 FAIL: decode response: %v", err)
	}
	if tokenResp["access_token"] != "opaque-access" {
		t.Fatalf("Step 4 FAIL: want access_token=opaque-access, got %v", tokenResp["access_token"])
	}
	if tokenResp["token_type"] != "Bearer" {
		t.Fatalf("Step 4 FAIL: want token_type=Bearer, got %v", tokenResp["token_type"])
	}
	if tokenResp["refresh_token"] != "opaque-refresh" {
		t.Fatalf("Step 4 FAIL: want refresh_token=opaque-refresh, got %v", tokenResp["refresh_token"])
	}
	t.Logf("Step 4 OK → access_token=%v expires_in=%v", tokenResp["access_token"], tokenResp["expires_in"])

	t.Log("Step 5: GET /api/projects (expect 200)")
	req5, _ := http.NewRequest(http.MethodGet, pubSrv.URL+"/api/projects", nil)
	req5.Header.Set("Authorization", "Bearer opaque-access")
	resp5, err := http.DefaultClient.Do(req5)
	if err != nil {
		t.Fatalf("Step 5 request failed: %v", err)
	}
	resp5.Body.Close()
	if resp5.StatusCode != http.StatusOK {
		t.Fatalf("Step 5 FAIL: want 200, got %d", resp5.StatusCode)
	}
	t.Log("Step 5 OK → /api/projects allowed by OPA")

	t.Log("Step 6: GET /api/secrets (expect 403)")
	req6, _ := http.NewRequest(http.MethodGet, pubSrv.URL+"/api/secrets", nil)
	req6.Header.Set("Authorization", "Bearer opaque-access")
	resp6, err := http.DefaultClient.Do(req6)
	if err != nil {
		t.Fatalf("Step 6 request failed: %v", err)
	}
	resp6.Body.Close()
	if resp6.StatusCode != http.StatusForbidden {
		t.Fatalf("Step 6 FAIL: want 403, got %d", resp6.StatusCode)
	}
	t.Log("Step 6 OK → /api/secrets denied by OPA")

	t.Log("All 6 steps passed")
}
