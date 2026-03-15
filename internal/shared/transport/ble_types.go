package transport

import (
	"errors"
	"time"
)

const (
	// BLEServiceUUID is the AckAgent GATT service UUID used for local transport.
	BLEServiceUUID = "A1B2C3D4-E5F6-4A5B-8C7D-9E0F1A2B3C4D"

	// BLERequestCharacteristicUUID is the write characteristic for requests.
	BLERequestCharacteristicUUID = "A1B2C3D4-E5F6-4A5B-8C7D-9E0F1A2B3C01"

	// BLEResponseCharacteristicUUID is the notify characteristic for responses.
	BLEResponseCharacteristicUUID = "A1B2C3D4-E5F6-4A5B-8C7D-9E0F1A2B3C02"

	// BLEStatusCharacteristicUUID is the read/notify characteristic for status.
	BLEStatusCharacteristicUUID = "A1B2C3D4-E5F6-4A5B-8C7D-9E0F1A2B3C03"
)

const (
	// DefaultBLEScanTimeout is the default duration for BLE scans.
	DefaultBLEScanTimeout = 5 * time.Second

	// DefaultBLEConnectTimeout is the default duration for BLE connections.
	DefaultBLEConnectTimeout = 5 * time.Second
)

var (
	// ErrBLEUnsupported indicates BLE is not supported on this platform.
	ErrBLEUnsupported = errors.New("bluetooth not supported on this platform")

	// ErrBLEDeviceNotFound indicates no matching BLE device was discovered.
	ErrBLEDeviceNotFound = errors.New("bluetooth device not found")
)

// BLETransportOptions configures the BLE transport.
type BLETransportOptions struct {
	// DeviceFilter matches by device name or address (case-insensitive).
	// Empty means the first discovered AckAgent device is used.
	DeviceFilter string

	// ScanTimeout controls how long discovery runs before failing.
	ScanTimeout time.Duration

	// ConnectTimeout controls how long to wait for a BLE connection.
	ConnectTimeout time.Duration
}

// BLEDeviceInfo contains BLE device discovery metadata.
type BLEDeviceInfo struct {
	Name    string
	Address string
	RSSI    int16
}
