package port

import "context"

type DeviceRepository interface {
	IsKnownDevice(ctx context.Context, userID, fingerprintHash string) (bool, error)
	SaveDevice(ctx context.Context, userID, fingerprintHash, uaHash string) error
}
