package httpadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/zero-trust/zero-trust-auth/services/gateway/internal/port"
)

type TrustClient struct {
	baseURL    string
	httpClient *http.Client
}

var _ port.TrustService = (*TrustClient)(nil)

func NewTrustClient(baseURL string) *TrustClient {
	return &TrustClient{baseURL: baseURL, httpClient: &http.Client{Timeout: 5 * time.Second}}
}

func (c *TrustClient) AnonymousCheck(ctx context.Context, rc port.RequestCtx) (bool, error) {
	body := map[string]string{
		"ip": rc.IP, "user_agent": rc.UserAgent, "fingerprint": rc.Fingerprint,
	}
	resp, err := c.post(ctx, "/trust/anonymous-check", body)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	var result struct {
		Decision string `json:"decision"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}
	return result.Decision == "ALLOW", nil
}

func (c *TrustClient) EvaluateTrust(ctx context.Context, userID string, roles []string, rc port.RequestCtx) (float64, string, error) {
	body := map[string]any{
		"user_id": userID, "roles": roles,
		"ip": rc.IP, "user_agent": rc.UserAgent, "fingerprint": rc.Fingerprint,
		"timestamp": time.Now().UTC(),
	}
	resp, err := c.post(ctx, "/trust/evaluate", body)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	var result struct {
		TrustScore float64 `json:"trust_score"`
		Decision   string  `json:"decision"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, "", err
	}
	return result.TrustScore, result.Decision, nil
}

func (c *TrustClient) post(ctx context.Context, path string, body any) (*http.Response, error) {
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
		return nil, fmt.Errorf("trust service %s: status %d", path, resp.StatusCode)
	}
	return resp, nil
}
