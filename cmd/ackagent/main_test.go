package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRootCommand_PersistentFlags(t *testing.T) {
	persistentFlags := rootCmd.PersistentFlags()

	expectedFlags := []struct {
		name      string
		shorthand string
		defValue  string
	}{
		{"config-dir", "c", ""},
		{"profile", "p", ""},
		{"org", "", ""},
		{"log-level", "", ""},
		{"ble-device", "", ""},
	}

	for _, tt := range expectedFlags {
		t.Run(tt.name, func(t *testing.T) {
			f := persistentFlags.Lookup(tt.name)
			require.NotNil(t, f, "persistent flag %q should exist", tt.name)
			assert.Equal(t, tt.defValue, f.DefValue, "flag %q default mismatch", tt.name)
			if tt.shorthand != "" {
				assert.Equal(t, tt.shorthand, f.Shorthand, "flag %q shorthand mismatch", tt.name)
			}
		})
	}
}

func TestRootCommand_Subcommands(t *testing.T) {
	expectedSubcommands := []string{
		"login",
		"gpg [file]",
		"age",
		"ssh",
		"keys",
		"hook",
		"profile",
		"org",
	}

	commands := rootCmd.Commands()
	commandUses := make([]string, len(commands))
	for i, cmd := range commands {
		commandUses[i] = cmd.Use
	}

	for _, expected := range expectedSubcommands {
		assert.Contains(t, commandUses, expected, "root should have %q subcommand", expected)
	}
}

func TestRootCommand_HasVersionFlag(t *testing.T) {
	// rootCmd.Version is set, which means cobra adds --version flag
	assert.NotEmpty(t, rootCmd.Version, "root command should have version set")
}

func TestRootCommand_UseLine(t *testing.T) {
	assert.Equal(t, "ackagent", rootCmd.Use, "root command use should be 'ackagent'")
}
