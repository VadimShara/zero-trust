package httpadapter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/zero-trust/zero-trust-auth/services/gateway/internal/port"
)

type IDPAdapterClient struct {
	baseURL    string
	httpClient *http.Client
}

var _ port.IDPAdapterService = (*IDPAdapterClient)(nil)

func NewIDPAdapterClient(baseURL string) *IDPAdapterClient {
	return &IDPAdapterClient{baseURL: baseURL, httpClient: &http.Client{Timeout: 5 * time.Second}}
}

func (c *IDPAdapterClient) GetLoginURL(ctx context.Context, state string) (string, error) {
	url := fmt.Sprintf("%s/idp/login-url?state=%s", c.baseURL, state)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("idpadapter: status %d", resp.StatusCode)
	}
	var result struct {
		LoginURL string `json:"login_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	return result.LoginURL, nil
}
