package port

import "context"

type IPInfo struct {
	Type         string
	ASN          string
	Country      string
	IsTor        bool
	IsDatacenter bool
}

// IPReputation looks up reputation for a raw IP address.
// Implementations are responsible for caching (Redis key: trust:ip:{sha256(ip)}).
type IPReputation interface {
	Lookup(ctx context.Context, ip string) (*IPInfo, error)
}
