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

type MFAClient struct {
	baseURL    string
	httpClient *http.Client
}

var _ port.MFAService = (*MFAClient)(nil)

func NewMFAClient(authServiceURL string) *MFAClient {
	return &MFAClient{baseURL: authServiceURL, httpClient: &http.Client{Timeout: 5 * time.Second}}
}

func (c *MFAClient) Setup(ctx context.Context, userID, email string) (*port.MFASetup, error) {
	body, _ := json.Marshal(map[string]string{"user_id": userID, "email": email})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/auth/mfa/setup", bytes.NewReader(body))
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
		return nil, fmt.Errorf("mfa setup: status %d", resp.StatusCode)
	}
	var result struct {
		Secret     string `json:"secret"`
		OTPAuthURI string `json:"otpauth_uri"`
		Enrolled   bool   `json:"enrolled"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &port.MFASetup{Secret: result.Secret, OTPAuthURI: result.OTPAuthURI, Enrolled: result.Enrolled}, nil
}

func (c *MFAClient) Verify(ctx context.Context, userID, code string) (bool, error) {
	body, _ := json.Marshal(map[string]string{"user_id": userID, "code": code})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/auth/mfa/verify", bytes.NewReader(body))
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
		return false, fmt.Errorf("mfa verify: status %d", resp.StatusCode)
	}
	var result struct {
		Valid bool `json:"valid"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}
	return result.Valid, nil
}
