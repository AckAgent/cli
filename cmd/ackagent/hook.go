package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ackagent/cli/internal/hook/claude"
)

var hookCmd = &cobra.Command{
	Use:   "hook",
	Short: "Approval hooks for various applications",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var claudeHookConfigure bool

var claudeHookCmd = &cobra.Command{
	Use:   "claude",
	Short: "Handle Claude Code PermissionRequest hooks",
	Run:   runClaudeHook,
}

func init() {
	claudeHookCmd.Flags().BoolVar(&claudeHookConfigure, "configure", false, "Configure Claude Code to use this hook")
	hookCmd.AddCommand(claudeHookCmd)
}

func runClaudeHook(cmd *cobra.Command, args []string) {
	if claudeHookConfigure {
		if err := claude.Configure(); err != nil {
			die("ackagent hook claude: %v", err)
		}
		return
	}

	// No flags, run the hook
	if err := claude.Run(); err != nil {
		// Exit code 2 signals blocking error to Claude Code
		fmt.Fprintf(os.Stderr, "ackagent hook: %v\n", err)
		os.Exit(2)
	}
}
