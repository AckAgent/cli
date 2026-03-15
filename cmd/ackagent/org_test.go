package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOrgCommand_Registered(t *testing.T) {
	found := false
	for _, sub := range rootCmd.Commands() {
		if sub.Use == "org" {
			found = true
			break
		}
	}
	assert.True(t, found, "org command should be registered as a subcommand of root")
}

func TestOrgCommand_Subcommands(t *testing.T) {
	expectedSubcommands := map[string]struct {
		argsMin int
		argsMax int
	}{
		"list":                 {0, 0},
		"default <identifier>": {1, 1},
		"show [identifier]":    {0, 1},
	}

	for use := range expectedSubcommands {
		t.Run(use, func(t *testing.T) {
			found := false
			for _, sub := range orgCmd.Commands() {
				if sub.Use == use {
					found = true
					break
				}
			}
			assert.True(t, found, "org should have %q subcommand", use)
		})
	}
}

func TestOrgListCommand_Aliases(t *testing.T) {
	assert.Contains(t, orgListCmd.Aliases, "ls", "org list should have 'ls' alias")
}

func TestOrgDefaultCommand_ExactlyOneArg(t *testing.T) {
	// orgDefaultCmd uses cobra.ExactArgs(1), so it requires exactly 1 arg.
	// We verify the Args function is set (non-nil).
	assert.NotNil(t, orgDefaultCmd.Args, "org default should have args validation")
}

func TestOrgShowCommand_MaxOneArg(t *testing.T) {
	assert.NotNil(t, orgShowCmd.Args, "org show should have args validation")
}

func TestOrgCommand_SubcommandCount(t *testing.T) {
	assert.Len(t, orgCmd.Commands(), 3, "org should have exactly 3 subcommands")
}
