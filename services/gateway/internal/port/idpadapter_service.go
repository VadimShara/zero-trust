package port

import "context"

type IDPAdapterService interface {
	GetLoginURL(ctx context.Context, state string) (string, error)
}
