package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

//go:embed templates/index.html
var indexHTML string

//go:embed templates/dashboard.html
var dashboardHTML string

type appConfig struct {
	GatewayURL       string
	GatewayPublicURL string
	ClientID         string
	ClientSecret     string
	Port             string
}

var cfg appConfig

const sessionCookie = "zt_sid"

type Session struct {
	ID            string
	State         string
	CodeVerifier  string
	AccessToken   string
	RefreshToken  string
	UserID        string
	Roles         []string
	TrustScore    float64
	TrustDecision string
	IP            string
	UserAgent     string
	Fingerprint   string
}

var (
	sessionsByID    sync.Map
	sessionsByState sync.Map
)

func newSession() *Session {
	s := &Session{ID: randHex(16)}
	sessionsByID.Store(s.ID, s)
	return s
}

func sessionByID(id string) *Session {
	v, ok := sessionsByID.Load(id)
	if !ok {
		return nil
	}
	return v.(*Session)
}

func sessionByState(state string) *Session {
	sid, ok := sessionsByState.Load(state)
	if !ok {
		return nil
	}
	return sessionByID(sid.(string))
}

func sessionFromCookie(r *http.Request) *Session {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil
	}
	return sessionByID(c.Value)
}

func setSessionCookie(w http.ResponseWriter, id string) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: id,
		Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 3600,
	})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/", MaxAge: -1})
}

func generateVerifier() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func pkceChallenge(v string) string {
	h := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

var hc = &http.Client{Timeout: 5 * time.Second}

type tokenResp struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type introspectResp struct {
	Active       bool                   `json:"active"`
	UserID       string                 `json:"user_id"`
	Roles        []string               `json:"roles"`
	TrustScore   float64                `json:"trust_score"`
	LoginSignals map[string]trustSignal `json:"login_signals"`
}

func exchangeCode(code, verifier string) (*tokenResp, error) {
	resp, err := hc.PostForm(cfg.GatewayURL+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"client_secret": {cfg.ClientSecret},
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("gateway %d: %s", resp.StatusCode, b)
	}
	var tr tokenResp
	json.NewDecoder(resp.Body).Decode(&tr)
	return &tr, nil
}

func introspect(token, ip, ua string) (*introspectResp, error) {
	body, _ := json.Marshal(map[string]string{"token": token})
	req, _ := http.NewRequest(http.MethodPost, cfg.GatewayURL+"/introspect", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Real-IP", ip)
	req.Header.Set("User-Agent", ua)
	req.Header.Set("X-TLS-Fingerprint", softFingerprint(req))
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var ir introspectResp
	json.NewDecoder(resp.Body).Decode(&ir)
	return &ir, nil
}

func revokeToken(token string) {
	body, _ := json.Marshal(map[string]bool{"logout_all": true})
	req, _ := http.NewRequest(http.MethodPost, cfg.GatewayURL+"/logout", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	hc.Do(req)
}

type trustSignal struct {
	Score  float64 `json:"score"`
	Weight float64 `json:"weight"`
}

type trustDetails struct {
	TrustScore float64                `json:"trust_score"`
	Decision   string                 `json:"decision"`
	Signals    map[string]trustSignal `json:"signals"`
}

type accessResult struct {
	Resource string `json:"resource"`
	Path     string `json:"path"`
	Method   string `json:"method"`
	Status   int    `json:"status"`
	Allowed  bool   `json:"allowed"`
	Reason   string `json:"reason"`
}

func testAccess(token, ip, ua, fingerprint, path, method string) *accessResult {
	req, _ := http.NewRequest(method, cfg.GatewayURL+path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Real-IP", ip)
	req.Header.Set("User-Agent", ua)
	if fingerprint != "" {
		req.Header.Set("X-TLS-Fingerprint", fingerprint)
	}

	resp, err := hc.Do(req)
	if err != nil {
		return &accessResult{Path: path, Reason: err.Error()}
	}
	defer resp.Body.Close()

	result := &accessResult{Path: path, Method: method, Status: resp.StatusCode}
	switch resp.StatusCode {
	case 200:
		result.Allowed = true
		result.Reason = "access granted"
	case 401:
		if strings.Contains(resp.Header.Get("WWW-Authenticate"), "insufficient_user_authentication") {
			result.Reason = "trust score too low — step-up MFA required"
		} else {
			result.Reason = "unauthorized"
		}
	case 403:
		result.Reason = "forbidden — insufficient role"
	default:
		b, _ := io.ReadAll(resp.Body)
		result.Reason = strings.TrimSpace(string(b))
	}
	return result
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	sess := sessionFromCookie(r)
	loggedIn := sess != nil && sess.AccessToken != ""
	shortID := ""
	if loggedIn && len(sess.UserID) >= 8 {
		shortID = sess.UserID[:8] + "…"
	}
	mustRender(w, indexHTML, nil, map[string]any{
		"LoggedIn": loggedIn, "ShortID": shortID,
	})
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	verifier, err := generateVerifier()
	if err != nil {
		http.Error(w, "internal error", 500)
		return
	}
	state := randHex(12)
	sess := newSession()
	sess.State = state
	sess.CodeVerifier = verifier
	sessionsByState.Store(state, sess.ID)
	setSessionCookie(w, sess.ID)

	redirect := cfg.GatewayPublicURL + "/authorize?" + url.Values{
		"client_id":             {cfg.ClientID},
		"code_challenge":        {pkceChallenge(verifier)},
		"code_challenge_method": {"S256"},
		"state":                 {state},
	}.Encode()
	http.Redirect(w, r, redirect, http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		http.Error(w, "missing code or state", 400)
		return
	}
	sess := sessionByState(state)
	if sess == nil {
		http.Error(w, "invalid state — try logging in again", 400)
		return
	}
	tr, err := exchangeCode(code, sess.CodeVerifier)
	if err != nil {
		http.Error(w, "token exchange failed: "+err.Error(), 502)
		return
	}
	sess.AccessToken = tr.AccessToken
	sess.RefreshToken = tr.RefreshToken
	sess.IP = realIP(r)
	sess.UserAgent = r.Header.Get("User-Agent")
	sess.Fingerprint = softFingerprint(r)

	if ir, err := introspect(tr.AccessToken, sess.IP, sess.UserAgent); err == nil && ir.Active {
		sess.UserID = ir.UserID
		sess.Roles = ir.Roles
		sess.TrustScore = ir.TrustScore
	}
	sessionsByState.Delete(state)
	setSessionCookie(w, sess.ID)
	target := "/dashboard"
	if sess.UserID != "" {
		target = "/dashboard?stepped_up=true"
	}
	http.Redirect(w, r, target, http.StatusFound)
}

var dashTmplFuncs = template.FuncMap{
	"short": func(s string) string {
		if len(s) > 8 {
			return s[:8] + "…"
		}
		return s
	},
	"initials": func(s string) string {
		if len(s) >= 2 {
			return strings.ToUpper(s[:2])
		}
		return "?"
	},
	"arc": func(f float64) string {
		return fmt.Sprintf("%.1f", f*314.16)
	},
	"arcRem": func(f float64) string {
		return fmt.Sprintf("%.1f", (1-f)*314.16)
	},
	"pct": func(f float64) int { return int(f * 100) },
	"decisionClass": func(d string) string {
		switch d {
		case "ALLOW":
			return "allow"
		case "MFA_REQUIRED", "STEP_UP":
			return "warn"
		default:
			return "deny"
		}
	},
	"decisionIcon": func(d string) string {
		switch d {
		case "ALLOW":
			return "✓"
		case "MFA_REQUIRED":
			return "🔑"
		case "STEP_UP":
			return "↑"
		default:
			return "✗"
		}
	},
	"signalColor": func(f float64) string {
		switch {
		case f >= 0.8:
			return "#10b981"
		case f >= 0.5:
			return "#f59e0b"
		default:
			return "#ef4444"
		}
	},
	"join":  strings.Join,
	"score": func(f float64) string { return fmt.Sprintf("%.2f", f) },
}

func doRefresh(refreshToken, ip, ua, fingerprint string) (*tokenResp, error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}
	req, err := http.NewRequest(http.MethodPost, cfg.GatewayURL+"/token",
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Real-IP", ip)
	req.Header.Set("User-Agent", ua)
	if fingerprint != "" {
		req.Header.Set("X-TLS-Fingerprint", fingerprint)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("refresh failed: status %d", resp.StatusCode)
	}
	var tr tokenResp
	json.NewDecoder(resp.Body).Decode(&tr)
	if tr.AccessToken == "" {
		return nil, fmt.Errorf("empty access token in refresh response")
	}
	return &tr, nil
}

func tryRefresh(w http.ResponseWriter, r *http.Request, sess *Session) bool {
	if sess.RefreshToken == "" {
		return false
	}
	ip := realIP(r)
	ua := r.Header.Get("User-Agent")
	fp := softFingerprint(r)

	tr, err := doRefresh(sess.RefreshToken, ip, ua, fp)
	if err != nil {
		return false
	}
	sess.AccessToken = tr.AccessToken
	sess.RefreshToken = tr.RefreshToken
	sess.IP = ip
	sess.UserAgent = ua
	sess.Fingerprint = fp

	if ir, err := introspect(tr.AccessToken, ip, ua); err == nil && ir.Active {
		sess.UserID = ir.UserID
		sess.Roles = ir.Roles
		sess.TrustScore = ir.TrustScore
	}
	setSessionCookie(w, sess.ID)
	return true
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromCookie(r)
	if sess == nil || sess.AccessToken == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	ir, err := introspect(sess.AccessToken, sess.IP, sess.UserAgent)
	if err != nil || !ir.Active {
		if !tryRefresh(w, r, sess) {
			clearSessionCookie(w)
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		ir, err = introspect(sess.AccessToken, sess.IP, sess.UserAgent)
		if err != nil || !ir.Active {
			clearSessionCookie(w)
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
	}
	sess.UserID = ir.UserID
	sess.Roles = ir.Roles
	sess.TrustScore = ir.TrustScore

	var td *trustDetails
	if ir.LoginSignals != nil {
		td = &trustDetails{
			TrustScore: ir.TrustScore,
			Signals:    ir.LoginSignals,
		}
	}
	mustRender(w, dashboardHTML, dashTmplFuncs, map[string]any{
		"Session": sess, "Trust": td,
	})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromCookie(r)
	if sess != nil && sess.AccessToken != "" {
		revokeToken(sess.AccessToken)
		sessionsByID.Delete(sess.ID)
	}
	clearSessionCookie(w)
	ssoLogout := cfg.GatewayPublicURL + "/sso-logout?redirect_uri=" +
		url.QueryEscape("http://localhost:4000/")
	http.Redirect(w, r, ssoLogout, http.StatusFound)
}

var resources = map[string]struct{ path, method, role, note string }{
	"projects": {"/api/projects", "GET", "developer", "trust ≥ 0.60"},
	"reports":  {"/api/reports", "GET", "viewer", "trust ≥ 0.60"},
	"secrets":  {"/api/secrets", "GET", "developer", "trust ≥ 0.85 (sensitive)"},
	"audit":    {"/audit/events", "GET", "security_admin", "trust ≥ 0.85 (sensitive)"},
	"admin":    {"/api/admin", "GET", "admin", "trust ≥ 0.85 (sensitive)"},
}

func handleTestAccess(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromCookie(r)
	if sess == nil || sess.AccessToken == "" {
		http.Error(w, "unauthorized", 401)
		return
	}
	resource := r.URL.Query().Get("resource")
	res, ok := resources[resource]
	if !ok {
		http.Error(w, "unknown resource", 400)
		return
	}
	result := testAccess(sess.AccessToken, sess.IP, sess.UserAgent, sess.Fingerprint, res.path, res.method)
	if result.Status == 401 && result.Reason == "unauthorized" {
		if tryRefresh(w, r, sess) {
			result = testAccess(sess.AccessToken, sess.IP, sess.UserAgent, sess.Fingerprint, res.path, res.method)
		}
	}
	result.Resource = resource
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func handleRefreshInfo(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromCookie(r)
	if sess == nil || sess.AccessToken == "" {
		http.Error(w, "unauthorized", 401)
		return
	}
	clearPublicIPCache()
	sess.IP = realIP(r)

	ir, err := introspect(sess.AccessToken, sess.IP, sess.UserAgent)
	if err != nil || !ir.Active {
		if !tryRefresh(w, r, sess) {
			http.Error(w, "unauthorized", 401)
			return
		}
		ir, err = introspect(sess.AccessToken, sess.IP, sess.UserAgent)
		if err != nil || !ir.Active {
			http.Error(w, "unauthorized", 401)
			return
		}
	}
	var td *trustDetails
	if ir.LoginSignals != nil {
		td = &trustDetails{TrustScore: ir.TrustScore, Signals: ir.LoginSignals}
		sess.TrustScore = ir.TrustScore
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"introspect": ir, "trust": td, "debug_ip": sess.IP})
}

func mustRender(w http.ResponseWriter, src string, funcs template.FuncMap, data any) {
	t := template.New("t")
	if funcs != nil {
		t = t.Funcs(funcs)
	}
	tmpl := template.Must(t.Parse(src))
	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, "render error: "+err.Error(), 500)
	}
}

func softFingerprint(r *http.Request) string {
	h := sha256.New()
	for _, hdr := range []string{
		r.Header.Get("User-Agent"),
		r.Header.Get("Accept"),
		r.Header.Get("Accept-Language"),
		r.Header.Get("Accept-Encoding"),
	} {
		h.Write([]byte(hdr + "|"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

var publicIPCache struct {
	sync.Mutex
	ip         string
	resolvedAt time.Time
}

const publicIPCacheTTL = 10 * time.Second

func clearPublicIPCache() {
	publicIPCache.Lock()
	publicIPCache.ip = ""
	publicIPCache.Unlock()
}

func resolvePublicIP() string {
	publicIPCache.Lock()
	defer publicIPCache.Unlock()

	if publicIPCache.ip != "" && time.Since(publicIPCache.resolvedAt) < publicIPCacheTTL {
		return publicIPCache.ip
	}

	for _, endpoint := range []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			cancel()
			continue
		}
		req.Header.Set("User-Agent", "zerotrust-client/1.0")
		resp, err := hc.Do(req)
		cancel()
		if err != nil || resp.StatusCode != http.StatusOK {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 64))
		resp.Body.Close()
		if err != nil {
			continue
		}
		ip := strings.TrimSpace(string(b))
		if net.ParseIP(ip) != nil {
			publicIPCache.ip = ip
			publicIPCache.resolvedAt = time.Now()
			return ip
		}
	}
	return publicIPCache.ip
}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true
	}
	for _, cidr := range []string{
		"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12",
		"192.168.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
	} {
		_, block, _ := net.ParseCIDR(cidr)
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

func realIP(r *http.Request) string {
	if ip := r.Header.Get("X-Browser-IP"); ip != "" && !isPrivateIP(ip) {
		return ip
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" && !isPrivateIP(ip) {
		return ip
	}
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		if first := strings.SplitN(ip, ",", 2)[0]; !isPrivateIP(strings.TrimSpace(first)) {
			return strings.TrimSpace(first)
		}
	}
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	if isPrivateIP(host) {
		if pub := resolvePublicIP(); pub != "" {
			return pub
		}
	}
	return host
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func requireEnv(log *slog.Logger, key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Error("required env var not set", "key", key)
		os.Exit(1)
	}
	return v
}

func handleStepUp(w http.ResponseWriter, r *http.Request) {
	verifier, err := generateVerifier()
	if err != nil {
		http.Error(w, "internal error", 500)
		return
	}
	state := randHex(12)

	sess := sessionFromCookie(r)
	if sess == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	sess.State = state
	sess.CodeVerifier = verifier
	sessionsByState.Store(state, sess.ID)

	redirect := cfg.GatewayPublicURL + "/authorize?" + url.Values{
		"client_id":             {cfg.ClientID},
		"code_challenge":        {pkceChallenge(verifier)},
		"code_challenge_method": {"S256"},
		"state":                 {state},
	}.Encode()
	http.Redirect(w, r, redirect, http.StatusFound)
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg = appConfig{
		GatewayURL:       env("GATEWAY_URL", "http://gateway:3000"),
		GatewayPublicURL: env("GATEWAY_PUBLIC_URL", "http://localhost:3000"),
		ClientID:         requireEnv(log, "CLIENT_ID"),
		ClientSecret:     requireEnv(log, "CLIENT_SECRET"),
		Port:             env("PORT", "4000"),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", handleIndex)
	mux.HandleFunc("GET /login", handleLogin)
	mux.HandleFunc("GET /callback", handleCallback)
	mux.HandleFunc("GET /dashboard", handleDashboard)
	mux.HandleFunc("POST /logout", handleLogout)
	mux.HandleFunc("GET /api/test-access", handleTestAccess)
	mux.HandleFunc("GET /api/refresh-info", handleRefreshInfo)
	mux.HandleFunc("GET /step-up", handleStepUp)

	log.Info("client app starting", "addr", ":"+cfg.Port)
	if err := http.ListenAndServe(":"+cfg.Port, mux); err != nil {
		log.Error("server failed", "error", err)
		os.Exit(1)
	}
}
