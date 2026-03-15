package claude

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ackagent/cli/internal/shared/config"
)

// ── saveAlwaysAllowRule ──────────────────────────────────────────────

func TestSaveAlwaysAllowRule_NilSettings(t *testing.T) {
	tmpDir := t.TempDir()
	config.SetConfigDir(tmpDir)
	defer config.ResetConfigDir()

	cfg := config.NewDefault()

	rule := config.AlwaysAllowRule{
		ID:        "rule-1",
		Tool:      "Bash",
		Pattern:   "ls *",
		CreatedAt: time.Now(),
	}

	if err := saveAlwaysAllowRule(cfg, rule); err != nil {
		t.Fatalf("saveAlwaysAllowRule() error = %v", err)
	}

	// Reload and verify rule was saved
	loaded, err := config.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	settings := loaded.HookSettings()
	if settings == nil {
		t.Fatal("HookSettings is nil after save")
	}
	if len(settings.AlwaysAllowRules) != 1 {
		t.Fatalf("AlwaysAllowRules count = %d, want 1", len(settings.AlwaysAllowRules))
	}
	if settings.AlwaysAllowRules[0].ID != "rule-1" {
		t.Errorf("rule ID = %q, want rule-1", settings.AlwaysAllowRules[0].ID)
	}
	if settings.AlwaysAllowRules[0].Tool != "Bash" {
		t.Errorf("rule Tool = %q, want Bash", settings.AlwaysAllowRules[0].Tool)
	}
	if settings.AlwaysAllowRules[0].Pattern != "ls *" {
		t.Errorf("rule Pattern = %q, want 'ls *'", settings.AlwaysAllowRules[0].Pattern)
	}
}

func TestSaveAlwaysAllowRule_ExistingSettings(t *testing.T) {
	tmpDir := t.TempDir()
	config.SetConfigDir(tmpDir)
	defer config.ResetConfigDir()

	cfg := config.NewDefault()

	// Set existing hook settings with a rule
	cfg.SetHookSettings(&config.HookSettings{
		FilteredTools: []string{"Bash", "Write"},
		AlwaysAllowRules: []config.AlwaysAllowRule{
			{ID: "existing-rule", Tool: "Write"},
		},
		TimeoutSeconds: 60,
	})
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}

	// Add a new rule
	rule := config.AlwaysAllowRule{
		ID:        "rule-2",
		Tool:      "Bash",
		Pattern:   "git *",
		CreatedAt: time.Now(),
	}
	if err := saveAlwaysAllowRule(cfg, rule); err != nil {
		t.Fatalf("saveAlwaysAllowRule() error = %v", err)
	}

	// Reload and verify both rules exist
	loaded, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	settings := loaded.HookSettings()
	if len(settings.AlwaysAllowRules) != 2 {
		t.Fatalf("AlwaysAllowRules count = %d, want 2", len(settings.AlwaysAllowRules))
	}
	// Existing rule preserved
	if settings.AlwaysAllowRules[0].ID != "existing-rule" {
		t.Errorf("first rule = %q, want existing-rule", settings.AlwaysAllowRules[0].ID)
	}
	// New rule appended
	if settings.AlwaysAllowRules[1].ID != "rule-2" {
		t.Errorf("second rule = %q, want rule-2", settings.AlwaysAllowRules[1].ID)
	}
}

// ── Configure ────────────────────────────────────────────────────────

func TestConfigure_NotLoggedIn(t *testing.T) {
	tmpDir := t.TempDir()
	config.SetConfigDir(tmpDir)
	defer config.ResetConfigDir()

	// Create a default config (not logged in)
	config.NewDefault()

	err := Configure()
	if err == nil {
		t.Error("Configure() should fail when not logged in")
	}
}

func TestConfigure_NoConfigFile(t *testing.T) {
	tmpDir := t.TempDir()
	config.SetConfigDir(tmpDir)
	defer config.ResetConfigDir()

	// Don't create any config — Load() will fail
	err := Configure()
	if err == nil {
		t.Error("Configure() should fail when config doesn't exist")
	}
}

func TestConfigure_LoggedIn(t *testing.T) {
	tmpDir := t.TempDir()
	config.SetConfigDir(tmpDir)
	defer config.ResetConfigDir()

	// Create a logged-in config
	cfg := config.NewDefault()
	profile, _ := cfg.GetActiveProfile()
	profile.UserAccount = &config.UserAccount{
		UserID:      "user-123",
		SASVerified: true,
		Devices: []config.UserDevice{
			{ApproverId: "device-1", PublicKey: []byte{0x01}},
		},
	}
	cfg.Save()

	// Create a fake ~/.claude directory in temp
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)

	err := Configure()
	if err != nil {
		t.Fatalf("Configure() error = %v", err)
	}

	// Verify settings.json was created
	settingsPath := filepath.Join(homeDir, ".claude", "settings.json")
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("Failed to read settings.json: %v", err)
	}

	var settings map[string]any
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatalf("Failed to parse settings.json: %v", err)
	}

	hooks, ok := settings["hooks"].(map[string]any)
	if !ok {
		t.Fatal("settings.json should have hooks section")
	}

	if _, ok := hooks["PermissionRequest"]; !ok {
		t.Error("hooks should have PermissionRequest")
	}
	if _, ok := hooks["PreToolUse"]; !ok {
		t.Error("hooks should have PreToolUse")
	}
}

func TestConfigure_MergesExistingSettings(t *testing.T) {
	tmpDir := t.TempDir()
	config.SetConfigDir(tmpDir)
	defer config.ResetConfigDir()

	// Create a logged-in config
	cfg := config.NewDefault()
	profile, _ := cfg.GetActiveProfile()
	profile.UserAccount = &config.UserAccount{
		UserID:      "user-123",
		SASVerified: true,
		Devices: []config.UserDevice{
			{ApproverId: "device-1", PublicKey: []byte{0x01}},
		},
	}
	cfg.Save()

	// Create an existing settings.json with custom content
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	claudeDir := filepath.Join(homeDir, ".claude")
	os.MkdirAll(claudeDir, 0755)

	existingSettings := map[string]any{
		"theme":        "dark",
		"custom_field": true,
	}
	data, _ := json.MarshalIndent(existingSettings, "", "  ")
	os.WriteFile(filepath.Join(claudeDir, "settings.json"), data, 0644)

	err := Configure()
	if err != nil {
		t.Fatalf("Configure() error = %v", err)
	}

	// Verify existing fields are preserved
	newData, _ := os.ReadFile(filepath.Join(claudeDir, "settings.json"))
	var settings map[string]any
	json.Unmarshal(newData, &settings)

	if settings["theme"] != "dark" {
		t.Error("existing 'theme' field was not preserved")
	}
	if settings["custom_field"] != true {
		t.Error("existing 'custom_field' was not preserved")
	}
	if _, ok := settings["hooks"]; !ok {
		t.Error("hooks were not added")
	}
}

func TestConfigure_InvalidExistingJSON(t *testing.T) {
	tmpDir := t.TempDir()
	config.SetConfigDir(tmpDir)
	defer config.ResetConfigDir()

	cfg := config.NewDefault()
	profile, _ := cfg.GetActiveProfile()
	profile.UserAccount = &config.UserAccount{
		UserID:      "user-123",
		SASVerified: true,
		Devices:     []config.UserDevice{{ApproverId: "d", PublicKey: []byte{0x01}}},
	}
	cfg.Save()

	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	claudeDir := filepath.Join(homeDir, ".claude")
	os.MkdirAll(claudeDir, 0755)

	// Write invalid JSON
	os.WriteFile(filepath.Join(claudeDir, "settings.json"), []byte("{invalid json"), 0644)

	err := Configure()
	if err == nil {
		t.Error("Configure() should fail with invalid existing JSON")
	}
}
