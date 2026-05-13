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

type GatewayClient struct {
	privateURL string
	httpClient *http.Client
}

var _ cases.GatewayService = (*GatewayClient)(nil)

func NewGatewayClient(privateURL string) *GatewayClient {
	return &GatewayClient{
		privateURL: privateURL,
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
}

func (c *GatewayClient) Continue(ctx context.Context, state, userID, email string, roles []string, rc cases.RequestCtx) error {
	body := map[string]any{
		"state":       state,
		"user_id":     userID,
		"email":       email,
		"roles":       roles,
		"request_ctx": rc,
	}
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.privateURL+"/internal/continue", bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("gateway: POST /internal/continue status %d", resp.StatusCode)
	}
	return nil
}
