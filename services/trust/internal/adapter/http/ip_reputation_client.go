package httpadapter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/zero-trust/zero-trust-auth/services/trust/internal/port"
	pkgerrors "github.com/zero-trust/zero-trust-auth/toolkit/pkg/errors"
)

const ipRepCacheTTL = time.Hour // trust:ip:{hash} TTL per Redis key schema

// ipCacheStore is the minimal interface the client needs; satisfied by
// *redisadapter.IPRepCache without importing that package directly.
type ipCacheStore interface {
	Get(ctx context.Context, ipHash string) (*port.IPInfo, error)
	Set(ctx context.Context, ipHash string, info *port.IPInfo, ttl time.Duration) error
}

// IPReputationClient implements port.IPReputation.
// On cache miss it calls an external HTTP API (IP_REPUTATION_API_URL).
// If API_KEY is empty the call is skipped and safe defaults are returned.
type IPReputationClient struct {
	cache      ipCacheStore
	httpClient *http.Client
	apiURL     string // e.g. https://api.example.com/v1/ip
	apiKey     string
	salt       string
}

var _ port.IPReputation = (*IPReputationClient)(nil)

func NewIPReputationClient(cache ipCacheStore, apiURL, apiKey, salt string) *IPReputationClient {
	return &IPReputationClient{
		cache:      cache,
		httpClient: &http.Client{Timeout: 3 * time.Second},
		apiURL:     apiURL,
		apiKey:     apiKey,
		salt:       salt,
	}
}

func (c *IPReputationClient) Lookup(ctx context.Context, ip string) (*port.IPInfo, error) {
	ipHash := hashIP(ip, c.salt)

	// cache hit
	if info, err := c.cache.Get(ctx, ipHash); err == nil {
		return info, nil
	} else if !errors.Is(err, pkgerrors.ErrNotFound) {
		return nil, err
	}

	// no API configured → safe defaults
	if c.apiKey == "" || c.apiURL == "" {
		return &port.IPInfo{Type: "residential", Country: "XX"}, nil
	}

	info, err := c.callExternalAPI(ctx, ip)
	if err != nil {
		// degrade gracefully — don't block the auth flow
		return &port.IPInfo{Type: "unknown"}, nil
	}

	_ = c.cache.Set(ctx, ipHash, info, ipRepCacheTTL)
	return info, nil
}

// apiResponse maps the JSON from the external IP reputation service.
// Modelled after common providers (IPQualityScore / AbuseIPDB).
type apiResponse struct {
	Tor     bool   `json:"tor"`
	VPN     bool   `json:"vpn"`
	Hosting bool   `json:"hosting"` // datacenter/cloud
	ISP     string `json:"isp"`
	Country string `json:"country_code"`
}

func (c *IPReputationClient) callExternalAPI(ctx context.Context, ip string) (*port.IPInfo, error) {
	url := fmt.Sprintf("%s/%s", c.apiURL, ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-Key", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ip reputation api: status %d", resp.StatusCode)
	}

	var ar apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&ar); err != nil {
		return nil, err
	}

	return &port.IPInfo{
		Type:         resolveType(ar),
		ASN:          ar.ISP,
		Country:      ar.Country,
		IsTor:        ar.Tor || ar.VPN,
		IsDatacenter: ar.Hosting,
	}, nil
}

func resolveType(ar apiResponse) string {
	switch {
	case ar.Tor:
		return "tor"
	case ar.VPN:
		return "vpn"
	case ar.Hosting:
		return "datacenter"
	default:
		return "residential"
	}
}

func hashIP(ip, salt string) string {
	h := sha256.Sum256([]byte(ip + salt))
	return hex.EncodeToString(h[:])
}
