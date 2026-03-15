package main

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSSHCommand_Registered(t *testing.T) {
	found := false
	for _, sub := range rootCmd.Commands() {
		if sub.Use == "ssh" {
			found = true
			break
		}
	}
	assert.True(t, found, "ssh command should be registered as a subcommand of root")
}

func TestSSHCommand_FlagsExist(t *testing.T) {
	flags := sshCmd.Flags()

	tests := []struct {
		flagName  string
		shorthand string
	}{
		{"generate-key", "g"},
		{"list-keys", "l"},
		{"key", "k"},
		{"output", "o"},
		{"name", "n"},
		{"type", "t"},
	}

	for _, tt := range tests {
		t.Run(tt.flagName, func(t *testing.T) {
			f := flags.Lookup(tt.flagName)
			require.NotNil(t, f, "flag %q should be defined", tt.flagName)
			assert.Equal(t, tt.shorthand, f.Shorthand, "flag %q should have shorthand %q", tt.flagName, tt.shorthand)
		})
	}
}

func TestSSHCommand_TypeDefaultsToECDSA(t *testing.T) {
	f := sshCmd.Flags().Lookup("type")
	require.NotNil(t, f)
	assert.Equal(t, "ecdsa", f.DefValue, "type flag should default to ecdsa (p256)")
}

func TestSSHCommand_BoolFlagsDefaultToFalse(t *testing.T) {
	for _, name := range []string{"generate-key", "list-keys"} {
		f := sshCmd.Flags().Lookup(name)
		require.NotNil(t, f)
		assert.Equal(t, "false", f.DefValue, "flag %q should default to false", name)
	}
}

func TestFindSKProviderPath(t *testing.T) {
	path, _ := findSKProviderPath()
	// The function should return a non-empty path regardless of whether the file exists
	assert.NotEmpty(t, path, "findSKProviderPath should always return a path")

	// Verify platform-appropriate extension
	if runtime.GOOS == "darwin" {
		assert.Contains(t, path, ".dylib", "macOS should use .dylib extension")
	} else {
		assert.Contains(t, path, ".so", "Linux should use .so extension")
	}

	// Path should contain the expected library name
	assert.Contains(t, path, "libackagent-sk")
}
