package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAgeCommand_Registered(t *testing.T) {
	found := false
	for _, sub := range rootCmd.Commands() {
		if sub.Use == "age" {
			found = true
			break
		}
	}
	assert.True(t, found, "age command should be registered as a subcommand of root")
}

func TestAgeCommand_Subcommands(t *testing.T) {
	expectedSubcommands := []string{"keygen", "recipient", "identity"}

	for _, name := range expectedSubcommands {
		t.Run(name, func(t *testing.T) {
			found := false
			for _, sub := range ageCmd.Commands() {
				if sub.Use == name {
					found = true
					break
				}
			}
			assert.True(t, found, "age should have %q subcommand", name)
		})
	}
}

func TestAgeKeygenCommand_LabelFlag(t *testing.T) {
	f := ageKeygenCmd.Flags().Lookup("label")
	require.NotNil(t, f, "keygen should have --label flag")
	assert.Equal(t, "l", f.Shorthand, "label flag should have -l shorthand")
	assert.Equal(t, "ackagent-age", f.DefValue, "label should default to 'ackagent-age'")
}

func TestAgeIdentityCommand_SaveFlag(t *testing.T) {
	f := ageIdentityCmd.Flags().Lookup("save")
	require.NotNil(t, f, "identity should have --save flag")
	assert.Equal(t, "s", f.Shorthand, "save flag should have -s shorthand")
	assert.Equal(t, "false", f.DefValue, "save should default to false")
}

func TestAgeCommand_SubcommandCount(t *testing.T) {
	// Should have exactly 3 subcommands: keygen, recipient, identity
	assert.Len(t, ageCmd.Commands(), 3, "age should have exactly 3 subcommands")
}
