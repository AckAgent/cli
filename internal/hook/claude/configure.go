package claude

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ackagent/cli/internal/shared/config"
)

// Configure sets up Claude Code to use the ackagent hook.
// It modifies ~/.claude/settings.json to add the PermissionRequest hook configuration.
func Configure() error {
	// Check if user is logged in
	cfg, err := config.Load()
	if err != nil || !cfg.IsLoggedIn() {
		return errors.New("not logged in. Run 'ackagent login' first")
	}

	// Get the path to the current executable
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	// Resolve symlinks to get the real path
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		return fmt.Errorf("failed to resolve executable path: %w", err)
	}

	// Get Claude settings path
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}
	claudeDir := filepath.Join(homeDir, ".claude")
	settingsPath := filepath.Join(claudeDir, "settings.json")

	// Ensure ~/.claude directory exists
	if err := os.MkdirAll(claudeDir, 0755); err != nil {
		return fmt.Errorf("failed to create %s: %w", claudeDir, err)
	}

	// Read existing settings or start with empty object
	settings := make(map[string]any)
	data, err := os.ReadFile(settingsPath)
	if err == nil {
		if err := json.Unmarshal(data, &settings); err != nil {
			return fmt.Errorf("failed to parse %s: %w", settingsPath, err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to read %s: %w", settingsPath, err)
	}

	// Build the hook configuration
	hookCommand := exePath + " hook claude"
	hookConfig := map[string]any{
		"type":    "command",
		"command": hookCommand,
		"timeout": 300,
	}

	// PermissionRequest hook for tool approvals (Bash, Write, Edit, etc.)
	permissionRequestConfig := []any{
		map[string]any{
			"hooks": []any{hookConfig},
		},
	}

	// PreToolUse hook for AskUserQuestion (remote answering)
	preToolUseConfig := []any{
		map[string]any{
			"matcher": "AskUserQuestion",
			"hooks":   []any{hookConfig},
		},
	}

	// Merge into existing settings
	hooks, ok := settings["hooks"].(map[string]any)
	if !ok {
		hooks = make(map[string]any)
	}
	hooks["PermissionRequest"] = permissionRequestConfig
	hooks["PreToolUse"] = preToolUseConfig
	settings["hooks"] = hooks

	// Write back with pretty printing
	output, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal settings: %w", err)
	}

	// Write atomically using temp file
	tmpPath := settingsPath + ".tmp"
	if err := os.WriteFile(tmpPath, output, 0644); err != nil {
		return fmt.Errorf("failed to write settings: %w", err)
	}
	if err := os.Rename(tmpPath, settingsPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to update settings: %w", err)
	}

	fmt.Printf("Configured Claude Code hook at %s\n", settingsPath)
	fmt.Printf("Using ackagent binary: %s\n", exePath)
	return nil
}
