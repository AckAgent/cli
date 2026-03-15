package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHookCommand_Registered(t *testing.T) {
	found := false
	for _, sub := range rootCmd.Commands() {
		if sub.Use == "hook" {
			found = true
			break
		}
	}
	assert.True(t, found, "hook command should be registered as a subcommand of root")
}

func TestHookCommand_HasClaudeSubcommand(t *testing.T) {
	found := false
	for _, sub := range hookCmd.Commands() {
		if sub.Use == "claude" {
			found = true
			break
		}
	}
	assert.True(t, found, "hook should have 'claude' subcommand")
}

func TestClaudeHookCommand_ConfigureFlag(t *testing.T) {
	f := claudeHookCmd.Flags().Lookup("configure")
	require.NotNil(t, f, "claude hook should have --configure flag")
	assert.Equal(t, "false", f.DefValue, "--configure should default to false")
}
