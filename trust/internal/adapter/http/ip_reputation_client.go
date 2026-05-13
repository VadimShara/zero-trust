package httpadapter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/zero-trust/zero-trust-auth/trust/internal/cases"
	pkgerrors "github.com/zero-trust/zero-trust-auth/toolkit/pkg/errors"
)

const ipRepCacheTTL = time.Hour

type ipCacheStore interface {
	Get(ctx context.Context, ipHash string) (*cases.IPInfo, error)
	Set(ctx context.Context, ipHash string, info *cases.IPInfo, ttl time.Duration) error
}

type IPReputationClient struct {
	cache      ipCacheStore
	httpClient *http.Client
	salt       string
}

var _ cases.IPReputation = (*IPReputationClient)(nil)

func NewIPReputationClient(cache ipCacheStore, _, _ string, salt string) *IPReputationClient {
	return &IPReputationClient{
		cache:      cache,
		httpClient: &http.Client{Timeout: 3 * time.Second},
		salt:       salt,
	}
}

func (c *IPReputationClient) Lookup(ctx context.Context, ip string) (*cases.IPInfo, error) {
	if isPrivateIP(ip) {
		return &cases.IPInfo{Type: "unknown", Country: ""}, nil
	}

	ipHash := hashIP(ip, c.salt)

	if info, err := c.cache.Get(ctx, ipHash); err == nil {
		return info, nil
	} else if !errors.Is(err, pkgerrors.ErrNotFound) {
		return nil, err
	}

	info, err := c.callIPAPI(ctx, ip)
	if err != nil {
		unknown := &cases.IPInfo{Type: "unknown"}
		_ = c.cache.Set(ctx, ipHash, unknown, 30*time.Second)
		return unknown, nil
	}

	_ = c.cache.Set(ctx, ipHash, info, ipRepCacheTTL)
	return info, nil
}

type ipAPIResponse struct {
	Status  string `json:"status"`
	Country string `json:"countryCode"`
	ISP     string `json:"isp"`
	Org     string `json:"org"`
	Proxy   bool   `json:"proxy"`
	Hosting bool   `json:"hosting"`
}

func (c *IPReputationClient) callIPAPI(ctx context.Context, ip string) (*cases.IPInfo, error) {
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,countryCode,isp,org,proxy,hosting", ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ip-api.com: status %d", resp.StatusCode)
	}

	var ar ipAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&ar); err != nil {
		return nil, err
	}
	if ar.Status != "success" {
		return nil, fmt.Errorf("ip-api.com: status=%s", ar.Status)
	}

	info := &cases.IPInfo{
		Country:      ar.Country,
		ASN:          ar.ISP,
		IsDatacenter: ar.Hosting,
		IsTor:        ar.Proxy,
	}
	switch {
	case ar.Proxy:
		info.Type = "proxy"
	case ar.Hosting:
		info.Type = "datacenter"
	default:
		info.Type = "residential"
	}
	return info, nil
}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true
	}
	private := []string{
		"127.0.0.0/8",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}
	for _, cidr := range private {
		_, block, _ := net.ParseCIDR(cidr)
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

func hashIP(ip, salt string) string {
	h := sha256.Sum256([]byte(ip + salt))
	return hex.EncodeToString(h[:])
}
