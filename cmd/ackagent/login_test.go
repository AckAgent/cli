package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoginCommand_Registered(t *testing.T) {
	found := false
	for _, sub := range rootCmd.Commands() {
		if sub.Use == "login" {
			found = true
			break
		}
	}
	assert.True(t, found, "login command should be registered as a subcommand of root")
}

func TestLoginCommand_FlagsExist(t *testing.T) {
	flags := loginCmd.Flags()

	tests := []struct {
		name     string
		defValue string
	}{
		{"localdev", "false"},
		{"sandbox", "false"},
		{"relay", ""},
		{"issuer", ""},
		{"device-name", ""},
		{"config", "false"},
		{"keys", "false"},
		{"logout", "false"},
		{"force", "false"},
		{"accept-software-approver-keys", "false"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := flags.Lookup(tt.name)
			require.NotNil(t, f, "flag %q should be defined", tt.name)
			assert.Equal(t, tt.defValue, f.DefValue, "flag %q default mismatch", tt.name)
		})
	}
}

func TestLoginCommand_ForceShorthand(t *testing.T) {
	f := loginCmd.Flags().Lookup("force")
	require.NotNil(t, f)
	assert.Equal(t, "f", f.Shorthand, "force should have -f shorthand")
}

func TestRenderQRWithLogo_EmptyBitmap(t *testing.T) {
	result := renderQRWithLogo([][]bool{}, []string{"X"})
	assert.Empty(t, result, "empty bitmap should produce empty output")
}

func TestRenderQRWithLogo_SmallBitmap(t *testing.T) {
	// Create a small 4x4 bitmap
	bitmap := [][]bool{
		{true, false, true, false},
		{false, true, false, true},
		{true, false, true, false},
		{false, true, false, true},
	}
	result := renderQRWithLogo(bitmap, []string{"X"})
	assert.NotEmpty(t, result, "should produce output for valid bitmap")
}
