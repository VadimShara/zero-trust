package httpadapter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

type AuditEvent struct {
	ID        string         `json:"id"`
	EventType string         `json:"event_type"`
	UserID    *string        `json:"user_id,omitempty"`
	Payload   map[string]any `json:"payload"`
	CreatedAt string         `json:"created_at"`
}

type AuditQueryResult struct {
	Events []AuditEvent `json:"events"`
	Total  int          `json:"total"`
	Limit  int          `json:"limit"`
	Offset int          `json:"offset"`
}

type AuditClient struct {
	baseURL    string
	httpClient *http.Client
}

func NewAuditClient(baseURL string) *AuditClient {
	return &AuditClient{baseURL: baseURL, httpClient: &http.Client{Timeout: 5 * time.Second}}
}

func (c *AuditClient) QueryEvents(ctx context.Context, params map[string]string) (*AuditQueryResult, error) {
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
	var result AuditQueryResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}
