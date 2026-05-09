package cases

import "context"

type IPInfo struct {
	Type         string
	ASN          string
	Country      string
	IsTor        bool
	IsDatacenter bool
}

type IPReputation interface {
	Lookup(ctx context.Context, ip string) (*IPInfo, error)
}
