package cases

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

)

type AnonymousCheckResult struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

type AnonymousCheckCase struct {
	ipRep  IPReputation
	cache  TrustCache
	salt   string
}

func NewAnonymousCheckCase(ipRep IPReputation, cache TrustCache, salt string) *AnonymousCheckCase {
	return &AnonymousCheckCase{ipRep: ipRep, cache: cache, salt: salt}
}

func (c *AnonymousCheckCase) Execute(ctx context.Context, ip, userAgent, fingerprint string) (*AnonymousCheckResult, error) {
	// 1. IP reputation check — blocks known bad IPs immediately
	info, err := c.ipRep.Lookup(ctx, ip)
	if err == nil && (info.IsDatacenter || info.IsTor) {
		return &AnonymousCheckResult{Decision: "DENY", Reason: "datacenter or tor exit node"}, nil
	}

	// 2. Per-IP rate limit (sliding 15-min window)
	ipHash := hashStr(ip, c.salt)
	fails, err := c.cache.IncrIPFails(ctx, ipHash)
	if err == nil && fails > 20 {
		return &AnonymousCheckResult{Decision: "DENY", Reason: "rate limit exceeded"}, nil
	}

	return &AnonymousCheckResult{Decision: "ALLOW"}, nil
}

func hashStr(s, salt string) string {
	h := sha256.Sum256([]byte(s + salt))
	return hex.EncodeToString(h[:])
}
