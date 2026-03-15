package transport

import (
	"testing"

	"github.com/ackagent/cli/internal/shared/config"
)

func TestNewRequestBuilder_BLEFromConfig(t *testing.T) {
	cfg := config.NewDefault()
	cfg.BLEEnabled = true
	cfg.BLEDevice = "test-device"

	b := NewRequestBuilder(cfg)

	if !b.managerConfig.EnableBLETransport {
		t.Error("expected BLE transport enabled from config")
	}
	if b.managerConfig.BLEDevice != "test-device" {
		t.Errorf("BLEDevice = %q, want %q", b.managerConfig.BLEDevice, "test-device")
	}
}

func TestRequestBuilder_WithManagerConfig(t *testing.T) {
	cfg := config.NewDefault()

	b := NewRequestBuilder(cfg)

	// Default should have BLE disabled
	if b.managerConfig.EnableBLETransport {
		t.Error("expected BLE transport disabled by default")
	}

	// Override with WithManagerConfig
	b.WithManagerConfig(ManagerConfig{
		EnableBLETransport: true,
		BLEDevice:          "override-device",
	})

	if !b.managerConfig.EnableBLETransport {
		t.Error("expected BLE transport enabled after WithManagerConfig")
	}
	if b.managerConfig.BLEDevice != "override-device" {
		t.Errorf("BLEDevice = %q, want %q", b.managerConfig.BLEDevice, "override-device")
	}
}
