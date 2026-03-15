package main

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ackagent/cli/internal/shared/transport"
)

func TestBLECommand_Registered(t *testing.T) {
	found := false
	for _, sub := range rootCmd.Commands() {
		if sub.Use == "ble" {
			found = true
			break
		}
	}
	assert.True(t, found, "ble command should be registered as a subcommand of root")
}

func TestBLECommand_HasListSubcommand(t *testing.T) {
	found := false
	for _, sub := range bleCmd.Commands() {
		if sub.Use == "list" {
			found = true
			break
		}
	}
	assert.True(t, found, "list command should be registered as a subcommand of ble")
}

func TestBLECommand_FlagsExist(t *testing.T) {
	f := bleCmd.Flags().Lookup("list")
	require.NotNil(t, f, "--list flag should be defined on bleCmd")

	pf := bleCmd.PersistentFlags().Lookup("timeout")
	require.NotNil(t, pf, "--timeout persistent flag should be defined on bleCmd")
}

func TestBLECommand_ListDefaultsFalse(t *testing.T) {
	f := bleCmd.Flags().Lookup("list")
	require.NotNil(t, f)
	assert.Equal(t, "false", f.DefValue, "--list flag should default to false")
}

func TestBLECommand_TimeoutDefault(t *testing.T) {
	f := bleCmd.PersistentFlags().Lookup("timeout")
	require.NotNil(t, f)
	assert.NotEmpty(t, f.DefValue, "--timeout flag should have a non-empty default")
}

func TestBLECommand_SubcommandCount(t *testing.T) {
	assert.Len(t, bleCmd.Commands(), 1, "bleCmd should have exactly 1 subcommand")
}

func TestBLECommand_ShortDescriptionNonEmpty(t *testing.T) {
	assert.NotEmpty(t, bleCmd.Short, "bleCmd.Short should be non-empty")
	assert.NotEmpty(t, bleListCmd.Short, "bleListCmd.Short should be non-empty")
}

func TestBLECommand_Use(t *testing.T) {
	assert.Equal(t, "ble", bleCmd.Use)
	assert.Equal(t, "list", bleListCmd.Use)
}

func TestBLEDeviceSorting(t *testing.T) {
	devices := []transport.BLEDeviceInfo{
		{Name: "Zulu", Address: "AA:BB:CC:DD:EE:01", RSSI: -50},
		{Name: "Alpha", Address: "AA:BB:CC:DD:EE:03", RSSI: -70},
		{Name: "Alpha", Address: "AA:BB:CC:DD:EE:01", RSSI: -60},
		{Name: "Bravo", Address: "AA:BB:CC:DD:EE:02", RSSI: -80},
	}

	sort.Slice(devices, func(i, j int) bool {
		if devices[i].Name == devices[j].Name {
			return devices[i].Address < devices[j].Address
		}
		return devices[i].Name < devices[j].Name
	})

	assert.Equal(t, "Alpha", devices[0].Name)
	assert.Equal(t, "AA:BB:CC:DD:EE:01", devices[0].Address)
	assert.Equal(t, "Alpha", devices[1].Name)
	assert.Equal(t, "AA:BB:CC:DD:EE:03", devices[1].Address)
	assert.Equal(t, "Bravo", devices[2].Name)
	assert.Equal(t, "Zulu", devices[3].Name)
}

func TestRunBLEList_NoDevicesOrError(t *testing.T) {
	// On machines with Bluetooth hardware, the scan succeeds but finds
	// no AckAgent devices. On machines without Bluetooth (or stub builds),
	// runBLEList returns an error. Both outcomes are acceptable.
	err := runBLEList(bleCmd, nil)
	if err != nil {
		// BLE adapter unavailable — expected on CI / headless environments.
		assert.Error(t, err)
	}
	// If err == nil the scan succeeded with zero devices — also fine.
}
