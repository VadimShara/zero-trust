package httpadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/zero-trust/zero-trust-auth/idpadapter/internal/cases"
)

type TrustClient struct {
	baseURL    string
	httpClient *http.Client
}

var _ cases.TrustService = (*TrustClient)(nil)

func NewTrustClient(baseURL string) *TrustClient {
	return &TrustClient{baseURL: baseURL, httpClient: &http.Client{Timeout: 5 * time.Second}}
}

func (c *TrustClient) SyncFails(ctx context.Context, userID string, count int64) error {
	body, err := json.Marshal(map[string]any{"user_id": userID, "count": count})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/trust/fails/sync", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("trust service /trust/fails/sync: status %d", resp.StatusCode)
	}
	return nil
}
