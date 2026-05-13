package httpadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/zero-trust/zero-trust-auth/gateway/internal/cases"
	"github.com/zero-trust/zero-trust-auth/gateway/internal/entities"
	pkgerrors "github.com/zero-trust/zero-trust-auth/toolkit/pkg/errors"
)

type TokenClient struct {
	baseURL    string
	httpClient *http.Client
}

var _ cases.TokenService = (*TokenClient)(nil)

func NewTokenClient(baseURL string) *TokenClient {
	return &TokenClient{baseURL: baseURL, httpClient: &http.Client{Timeout: 5 * time.Second}}
}

func (c *TokenClient) Issue(ctx context.Context, userID string, roles []string, trustScore float64, loginSignals map[string]entities.Signal) (string, string, error) {
	body := map[string]any{"user_id": userID, "roles": roles, "trust_score": trustScore, "login_signals": loginSignals}

	resp, err := c.post(ctx, "/tokens/issue", body)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	var result struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", err
	}

	return result.AccessToken, result.RefreshToken, nil
}

func (c *TokenClient) Introspect(ctx context.Context, token string, rc cases.RequestCtx) (bool, string, []string, float64, map[string]entities.Signal, error) {
	body := map[string]any{"token": token, "ip": rc.IP, "user_agent": rc.UserAgent, "fingerprint": rc.Fingerprint}

	resp, err := c.post(ctx, "/tokens/introspect", body)
	if err != nil {
		return false, "", nil, 0, nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Active       bool                        `json:"active"`
		UserID       string                      `json:"user_id"`
		Roles        []string                    `json:"roles"`
		TrustScore   float64                     `json:"trust_score"`
		LoginSignals map[string]entities.Signal  `json:"login_signals"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, "", nil, 0, nil, err
	}

	return result.Active, result.UserID, result.Roles, result.TrustScore, result.LoginSignals, nil
}

func (c *TokenClient) Refresh(ctx context.Context, refreshToken string, rc cases.RequestCtx) (string, string, error) {
	body := map[string]any{
		"refresh_token": refreshToken,
		"ip":            rc.IP, "user_agent": rc.UserAgent, "fingerprint": rc.Fingerprint,
	}

	data, _ := json.Marshal(body)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/tokens/refresh", bytes.NewReader(data))
	if err != nil {
		return "", "", err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		var errBody struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errBody)

		if errBody.Error == "token_reuse_detected" {
			return "", "", pkgerrors.ErrTokenReuse
		}

		return "", "", pkgerrors.ErrTokenExpired
	}

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("token service /tokens/refresh: status %d", resp.StatusCode)
	}

	var result struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", err
	}

	return result.AccessToken, result.RefreshToken, nil
}

func (c *TokenClient) AdminRevokeUser(ctx context.Context, userID, adminID, reason string) (int, error) {
	body := map[string]string{"user_id": userID, "admin_id": adminID, "reason": reason}

	resp, err := c.post(ctx, "/tokens/admin/revoke-user", body)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	var result struct {
		RevokedFamilies int `json:"revoked_families"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, err
	}

	return result.RevokedFamilies, nil
}

func (c *TokenClient) Revoke(ctx context.Context, token string, revokeAll bool) error {
	body := map[string]any{"token": token, "revoke_family": revokeAll}

	resp, err := c.post(ctx, "/tokens/revoke", body)
	if err != nil {
		return err
	}
	resp.Body.Close()

	return nil
}

func (c *TokenClient) post(ctx context.Context, path string, body any) (*http.Response, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("token service %s: status %d", path, resp.StatusCode)
	}

	return resp, nil
}
