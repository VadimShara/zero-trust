package keycloak

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type AdminClient struct {
	internalBaseURL string
	realm           string
	adminUsername   string
	adminPassword   string
	httpClient      *http.Client
}

func NewAdminClient(internalBaseURL, realm, adminUsername, adminPassword string) *AdminClient {
	return &AdminClient{
		internalBaseURL: internalBaseURL,
		realm:           realm,
		adminUsername:   adminUsername,
		adminPassword:   adminPassword,
		httpClient:      &http.Client{Timeout: 5 * time.Second},
	}
}

func (c *AdminClient) GetFailureCount(ctx context.Context, kcUserID string) (int64, error) {
	token, err := c.getAdminToken(ctx)
	if err != nil {
		return 0, fmt.Errorf("keycloak admin token: %w", err)
	}

	endpoint := fmt.Sprintf("%s/admin/realms/%s/attack-detection/brute-force/users/%s",
		c.internalBaseURL, c.realm, kcUserID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("keycloak brute-force query: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("keycloak brute-force: status %d: %s", resp.StatusCode, body)
	}

	var result struct {
		NumFailures int64 `json:"numFailures"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, err
	}
	return result.NumFailures, nil
}

func (c *AdminClient) getAdminToken(ctx context.Context) (string, error) {
	tokenURL := fmt.Sprintf("%s/realms/master/protocol/openid-connect/token", c.internalBaseURL)

	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {"admin-cli"},
		"username":   {c.adminUsername},
		"password":   {c.adminPassword},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("admin token: status %d", resp.StatusCode)
	}

	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return "", err
	}
	return tok.AccessToken, nil
}
