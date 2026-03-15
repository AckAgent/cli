package transport

import (
	"github.com/ackagent/cli/internal/shared/config"
)

// ManagerConfig holds configuration for the transport manager.
type ManagerConfig struct {
	// EnableBLETransport enables BLE local transport for direct device communication.
	EnableBLETransport bool

	// BLEDevice selects the BLE device by name or address (case-insensitive).
	BLEDevice string
}

// DefaultManagerConfig returns the default manager configuration.
func DefaultManagerConfig() ManagerConfig {
	return ManagerConfig{
		EnableBLETransport: false,
		BLEDevice:          "",
	}
}

// NewManagerWithConfig creates a transport manager with the given configuration.
func NewManagerWithConfig(cfg *config.Config, accessToken string, mgrCfg ManagerConfig) *Manager {
	m := NewManager()

	if mgrCfg.EnableBLETransport {
		m.Register(NewBLETransport(BLETransportOptions{
			DeviceFilter: mgrCfg.BLEDevice,
		}))
	}

	relay := NewRelayTransport(cfg.RelayURL(), cfg.DeviceID)
	relay.SetAccessToken(accessToken)
	m.Register(relay)

	return m
}
