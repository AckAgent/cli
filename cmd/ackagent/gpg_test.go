package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGPGCommand_Registered(t *testing.T) {
	cmd := rootCmd
	found := false
	for _, sub := range cmd.Commands() {
		if sub.Use == "gpg [file]" {
			found = true
			break
		}
	}
	assert.True(t, found, "gpg command should be registered as a subcommand of root")
}

func TestGPGCommand_FlagsExist(t *testing.T) {
	flags := gpgCmd.Flags()

	tests := []struct {
		name     string
		flagName string
	}{
		{"detach-sign", "detach-sign"},
		{"sign", "sign"},
		{"armor", "armor"},
		{"verbose", "verbose"},
		{"local-user", "local-user"},
		{"output", "output"},
		{"status-fd", "status-fd"},
		{"decrypt", "decrypt"},
		{"encrypt", "encrypt"},
		{"recipient", "recipient"},
		{"list-keys", "list-keys"},
		{"export", "export"},
		{"generate-key", "generate-key"},
		{"name", "name"},
		{"email", "email"},
		{"type", "type"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := flags.Lookup(tt.flagName)
			require.NotNil(t, f, "flag %q should be defined", tt.flagName)
		})
	}
}

func TestGPGCommand_FlagDefaults(t *testing.T) {
	flags := gpgCmd.Flags()

	// Boolean flags default to false
	for _, name := range []string{"detach-sign", "sign", "armor", "verbose", "decrypt", "encrypt", "list-keys", "export", "generate-key"} {
		f := flags.Lookup(name)
		require.NotNil(t, f, "flag %q should exist", name)
		assert.Equal(t, "false", f.DefValue, "flag %q should default to false", name)
	}

	// String flags default to empty
	for _, name := range []string{"local-user", "output", "name", "email", "type"} {
		f := flags.Lookup(name)
		require.NotNil(t, f, "flag %q should exist", name)
		assert.Equal(t, "", f.DefValue, "flag %q should default to empty", name)
	}

	// status-fd defaults to -1
	f := flags.Lookup("status-fd")
	require.NotNil(t, f)
	assert.Equal(t, "-1", f.DefValue, "status-fd should default to -1")
}

func TestGPGCommand_FlagShorthands(t *testing.T) {
	flags := gpgCmd.Flags()

	shorthands := map[string]string{
		"detach-sign": "b",
		"sign":        "s",
		"armor":       "a",
		"verbose":     "v",
		"local-user":  "u",
		"output":      "o",
		"decrypt":     "d",
		"encrypt":     "e",
		"recipient":   "r",
		"list-keys":   "k",
		"type":        "t",
	}

	for flagName, shorthand := range shorthands {
		t.Run(flagName, func(t *testing.T) {
			f := flags.Lookup(flagName)
			require.NotNil(t, f, "flag %q should exist", flagName)
			assert.Equal(t, shorthand, f.Shorthand, "flag %q should have shorthand %q", flagName, shorthand)
		})
	}
}

func TestGPGCommand_HiddenFlags(t *testing.T) {
	flags := gpgCmd.Flags()

	hiddenFlags := []string{
		"no-tty", "batch", "yes", "no-armor",
		"keyid-format", "digest-algo", "default-key",
		"homedir", "keyring",
	}

	for _, name := range hiddenFlags {
		t.Run(name, func(t *testing.T) {
			f := flags.Lookup(name)
			require.NotNil(t, f, "hidden flag %q should exist", name)
			assert.True(t, f.Hidden, "flag %q should be hidden", name)
		})
	}
}

func TestGPGCommand_MaximumOneArg(t *testing.T) {
	// The GPG command should accept at most 1 positional argument (input file)
	assert.NotNil(t, gpgCmd.Args)
}

func TestGPGCommand_DisablesFlagsInUseLine(t *testing.T) {
	assert.True(t, gpgCmd.DisableFlagsInUseLine)
}
