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

// OPAClient implements port.PolicyEngine against Open Policy Agent.
// POST {opaURL}/v1/data/authz/allow with input JSON.
type OPAClient struct {
	endpoint   string // e.g. http://opa:8181/v1/data/authz/allow
	httpClient *http.Client
}

var _ port.PolicyEngine = (*OPAClient)(nil)

func NewOPAClient(opaURL string) *OPAClient {
	return &OPAClient{
		endpoint:   opaURL + "/v1/data/authz/allow",
		httpClient: &http.Client{Timeout: 3 * time.Second},
	}
}

func (c *OPAClient) Allow(ctx context.Context, userID string, roles []string, trustScore float64, resource, action string) (bool, error) {
	payload := map[string]any{
		"input": map[string]any{
			"user":     map[string]any{"roles": roles, "trust_score": trustScore},
			"resource": resource,
			"action":   action,
		},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return false, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(data))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("opa: status %d", resp.StatusCode)
	}

	var result struct {
		Result bool `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}
	return result.Result, nil
}
