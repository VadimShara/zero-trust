package httpadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/zero-trust/zero-trust-auth/gateway/internal/cases"
)

// OPAClient implements cases.PolicyEngine against Open Policy Agent.
// Queries /v1/data/authz (the whole package) to get both `allow` and
// `deny_reason` in a single round-trip — no second request needed.
type OPAClient struct {
	endpoint   string // e.g. http://opa:8181/v1/data/authz
	httpClient *http.Client
}

var _ cases.PolicyEngine = (*OPAClient)(nil)

func NewOPAClient(opaURL string) *OPAClient {
	return &OPAClient{
		endpoint:   opaURL + "/v1/data/authz",
		httpClient: &http.Client{Timeout: 3 * time.Second},
	}
}

func (c *OPAClient) Decide(ctx context.Context, userID string, roles []string, trustScore float64, resource, action string) (*cases.PolicyDecision, error) {
	payload := map[string]any{
		"input": map[string]any{
			"user":     map[string]any{"roles": roles, "trust_score": trustScore},
			"resource": resource,
			"action":   action,
		},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("opa: status %d", resp.StatusCode)
	}

	// OPA returns the whole authz package: {result: {allow: bool, deny_reason: string}}
	var body struct {
		Result struct {
			Allow      bool   `json:"allow"`
			DenyReason string `json:"deny_reason"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	return &cases.PolicyDecision{
		Allow:      body.Result.Allow,
		DenyReason: body.Result.DenyReason,
	}, nil
}
