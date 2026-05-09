package httpadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/zero-trust/zero-trust-auth/token/internal/cases"
)

type TrustClient struct {
	baseURL    string
	httpClient *http.Client
}

var _ cases.TrustService = (*TrustClient)(nil)

func NewTrustClient(baseURL string) *TrustClient {
	return &TrustClient{
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
}

func (c *TrustClient) Evaluate(ctx context.Context, tc cases.TrustContext) (float64, string, error) {
	body := map[string]any{
		"user_id":     tc.UserID.String(),
		"ip":          tc.IP,
		"user_agent":  tc.UserAgent,
		"fingerprint": tc.Fingerprint,
		"timestamp":   time.Now().UTC(),
	}
	data, err := json.Marshal(body)
	if err != nil {
		return 0, "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/trust/evaluate", bytes.NewReader(data))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, "", fmt.Errorf("trust service: status %d", resp.StatusCode)
	}

	var result struct {
		TrustScore float64 `json:"trust_score"`
		Decision   string  `json:"decision"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, "", err
	}
	return result.TrustScore, result.Decision, nil
}
