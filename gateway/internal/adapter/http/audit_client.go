package httpadapter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/zero-trust/zero-trust-auth/gateway/internal/cases"
)

type AuditClient struct {
	baseURL    string
	httpClient *http.Client
}

func NewAuditClient(baseURL string) *AuditClient {
	return &AuditClient{baseURL: baseURL, httpClient: &http.Client{Timeout: 5 * time.Second}}
}

func (c *AuditClient) QueryEvents(ctx context.Context, params map[string]string) (*cases.AuditQueryResult, error) {
	q := url.Values{}

	for k, v := range params {
		if v != "" {
			q.Set(k, v)
		}
	}

	endpoint := c.baseURL + "/audit/events"

	if len(q) > 0 {
		endpoint += "?" + q.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("audit service: status %d", resp.StatusCode)
	}

	var result cases.AuditQueryResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}
