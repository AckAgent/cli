package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProfileCommand_Registered(t *testing.T) {
	found := false
	for _, sub := range rootCmd.Commands() {
		if sub.Use == "profile" {
			found = true
			break
		}
	}
	assert.True(t, found, "profile command should be registered as a subcommand of root")
}

func TestProfileCommand_Subcommands(t *testing.T) {
	expectedSubcommands := []string{
		"list",
		"use <name>",
		"show [name]",
		"rename <old> <new>",
		"delete <name>",
	}

	for _, use := range expectedSubcommands {
		t.Run(use, func(t *testing.T) {
			found := false
			for _, sub := range profileCmd.Commands() {
				if sub.Use == use {
					found = true
					break
				}
			}
			assert.True(t, found, "profile should have %q subcommand", use)
		})
	}
}

func TestProfileCommand_SubcommandCount(t *testing.T) {
	assert.Len(t, profileCmd.Commands(), 5, "profile should have exactly 5 subcommands")
}

func TestProfileListCommand_Aliases(t *testing.T) {
	assert.Contains(t, profileListCmd.Aliases, "ls", "profile list should have 'ls' alias")
}

func TestProfileUseCommand_Aliases(t *testing.T) {
	assert.Contains(t, profileUseCmd.Aliases, "switch", "profile use should have 'switch' alias")
}

func TestProfileRenameCommand_Aliases(t *testing.T) {
	assert.Contains(t, profileRenameCmd.Aliases, "mv", "profile rename should have 'mv' alias")
}

func TestProfileDeleteCommand_Aliases(t *testing.T) {
	assert.Contains(t, profileDeleteCmd.Aliases, "rm", "profile delete should have 'rm' alias")
}

func TestProfileUseCommand_RequiresOneArg(t *testing.T) {
	assert.NotNil(t, profileUseCmd.Args, "profile use should have args validation")
}

func TestProfileRenameCommand_RequiresTwoArgs(t *testing.T) {
	assert.NotNil(t, profileRenameCmd.Args, "profile rename should have args validation")
}

func TestProfileDeleteCommand_RequiresOneArg(t *testing.T) {
	assert.NotNil(t, profileDeleteCmd.Args, "profile delete should have args validation")
}

func TestTruncateFingerprint(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
	}{
		// 40 chars, last 16 = "34567890ABCDEF12"
		{"long fingerprint", "ABCDEF1234567890ABCDEF1234567890ABCDEF12", "...34567890ABCDEF12"},
		{"exactly 16 chars", "1234567890123456", "1234567890123456"},
		{"short fingerprint", "ABCD", "ABCD"},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncateFingerprint(tt.input)
			assert.Equal(t, tt.expect, result)
		})
	}
}
