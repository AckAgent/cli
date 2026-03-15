//go:build (!darwin && !linux) || disable_ble

package transport

import (
	"context"
	"time"
)

// BLETransport is a stub transport for unsupported platforms.
type BLETransport struct{}

// NewBLETransport creates a BLE transport stub.
func NewBLETransport(opts BLETransportOptions) *BLETransport {
	return &BLETransport{}
}

// Name returns the transport name.
func (t *BLETransport) Name() string {
	return "bluetooth"
}

// Priority returns the transport priority.
func (t *BLETransport) Priority() int {
	return 10
}

// IsAvailable always returns false on unsupported platforms.
func (t *BLETransport) IsAvailable(ctx context.Context) (bool, error) {
	return false, ErrBLEUnsupported
}

// Send always returns ErrBLEUnsupported on unsupported platforms.
func (t *BLETransport) Send(ctx context.Context, req *Request, timeout time.Duration) (*Response, error) {
	return nil, ErrBLEUnsupported
}

// ScanBLEDevices returns ErrBLEUnsupported on unsupported platforms.
func ScanBLEDevices(ctx context.Context, timeout time.Duration) ([]BLEDeviceInfo, error) {
	return nil, ErrBLEUnsupported
}
