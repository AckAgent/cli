package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSaveProfile_Existing(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()
	profile, _ := cfg.GetActiveProfile()
	profile.RelayURL = "http://save-profile-test.example.com"

	if err := cfg.SaveProfile(DefaultProfileName); err != nil {
		t.Fatalf("SaveProfile() error = %v", err)
	}

	// Verify the file was written
	data, err := os.ReadFile(ProfilePath(DefaultProfileName))
	if err != nil {
		t.Fatalf("reading profile file: %v", err)
	}
	var loaded ProfileConfig
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("parsing profile: %v", err)
	}
	if loaded.RelayURL != "http://save-profile-test.example.com" {
		t.Errorf("RelayURL = %q, want http://save-profile-test.example.com", loaded.RelayURL)
	}
}

func TestSaveProfile_NotFound(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()
	err := cfg.SaveProfile("nonexistent")
	if err == nil {
		t.Error("SaveProfile(nonexistent) should error")
	}
}

func TestCleanupOldBackups_KeepsMaxBackups(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	// Save initial config
	cfg := NewDefault()
	cfg.Save()

	// Create more than maxBackups backup files
	dir := ConfigDir()
	for i := 0; i < maxBackups+3; i++ {
		ts := time.Date(2024, 1, 1+i, 0, 0, 0, 0, time.UTC).Format("2006-01-02T15-04-05")
		path := filepath.Join(dir, "config.json.backup."+ts)
		os.WriteFile(path, []byte("{}"), 0600)
	}

	cleanupOldBackups()

	// Check only maxBackups remain
	matches, _ := filepath.Glob(filepath.Join(dir, "config.json.backup.*"))
	if len(matches) != maxBackups {
		t.Errorf("expected %d backups after cleanup, got %d", maxBackups, len(matches))
	}
}

func TestCleanupOldBackups_FewBackups_NoOp(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	// Set up config dir manually (don't use NewDefault which calls Save)
	dir := ConfigDir()
	os.MkdirAll(dir, 0700)

	// Create fewer than maxBackups
	for i := 0; i < 2; i++ {
		ts := time.Date(2024, 1, 1+i, 0, 0, 0, 0, time.UTC).Format("2006-01-02T15-04-05")
		path := filepath.Join(dir, "config.json.backup."+ts)
		os.WriteFile(path, []byte("{}"), 0600)
	}

	cleanupOldBackups()

	matches, _ := filepath.Glob(filepath.Join(dir, "config.json.backup.*"))
	if len(matches) != 2 {
		t.Errorf("expected 2 backups (untouched), got %d", len(matches))
	}
}

func TestBackupConfig_NoExistingConfig(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	// No config file exists yet
	err := backupConfig()
	if err != nil {
		t.Errorf("backupConfig() with no config should not error, got: %v", err)
	}
}

func TestBackupConfig_CreatesBackup(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()
	cfg.Save()

	err := backupConfig()
	if err != nil {
		t.Fatalf("backupConfig() error = %v", err)
	}

	matches, _ := filepath.Glob(filepath.Join(ConfigDir(), "config.json.backup.*"))
	if len(matches) == 0 {
		t.Error("expected at least one backup file")
	}
}

func TestLoad_CorruptConfig(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	// Write invalid JSON
	dir := ConfigDir()
	os.MkdirAll(dir, 0700)
	os.WriteFile(ConfigPath(), []byte("not-valid-json{"), 0600)

	_, err := Load()
	if err == nil {
		t.Error("Load() should fail for corrupt JSON")
	}
}

func TestLoad_NoProfilesDir(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	// Write a valid minimal config but no profiles directory
	dir := ConfigDir()
	os.MkdirAll(dir, 0700)
	data, _ := json.Marshal(map[string]any{
		"version":        ConfigVersion,
		"device_id":      "test-device",
		"device_name":    "Test",
		"active_profile": DefaultProfileName,
	})
	os.WriteFile(ConfigPath(), data, 0600)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.DeviceID != "test-device" {
		t.Errorf("DeviceID = %q, want test-device", cfg.DeviceID)
	}
	// No profiles loaded since dir doesn't exist
	if len(cfg.Profiles) != 0 {
		t.Errorf("expected 0 profiles, got %d", len(cfg.Profiles))
	}
}

func TestLoad_WithBadProfileFile(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()
	cfg.Save()

	// Write a bad profile file alongside the good one
	os.WriteFile(ProfilePath("bad"), []byte("not json"), 0600)

	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v (should skip bad profile)", err)
	}
	// The good default profile should still load
	if _, ok := loaded.Profiles[DefaultProfileName]; !ok {
		t.Error("default profile should still be loaded")
	}
	// The bad profile should be skipped
	if _, ok := loaded.Profiles["bad"]; ok {
		t.Error("bad profile should not be loaded")
	}
}

func TestSaveConfigOnly_RoundTrip(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := &Config{
		Version:       ConfigVersion,
		DeviceID:      "test-id",
		DeviceName:    "test-machine",
		ActiveProfile: "prod",
		Profiles:      map[string]*ProfileConfig{},
	}

	if err := cfg.saveConfigOnly(); err != nil {
		t.Fatalf("saveConfigOnly() error = %v", err)
	}

	// Read back and verify
	data, err := os.ReadFile(ConfigPath())
	if err != nil {
		t.Fatalf("reading config: %v", err)
	}

	var raw map[string]any
	json.Unmarshal(data, &raw)
	if raw["device_id"] != "test-id" {
		t.Errorf("device_id = %v, want test-id", raw["device_id"])
	}
	if raw["active_profile"] != "prod" {
		t.Errorf("active_profile = %v, want prod", raw["active_profile"])
	}
}

func TestSave_MultipleProfiles(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()
	cfg.CreateProfile("sandbox", "https://sandbox.example.com", "https://auth.sandbox.example.com")
	sandbox, _ := cfg.GetProfile("sandbox")
	sandbox.Keys = []KeyMetadata{
		{IOSKeyID: "sb-key-1", Label: "Sandbox Key"},
	}

	if err := cfg.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Both profile files should exist
	if _, err := os.Stat(ProfilePath(DefaultProfileName)); os.IsNotExist(err) {
		t.Error("default profile file missing")
	}
	if _, err := os.Stat(ProfilePath("sandbox")); os.IsNotExist(err) {
		t.Error("sandbox profile file missing")
	}

	// Reload and verify
	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(loaded.Profiles) != 2 {
		t.Errorf("expected 2 profiles, got %d", len(loaded.Profiles))
	}
	sbProfile, _ := loaded.GetProfile("sandbox")
	if len(sbProfile.Keys) != 1 {
		t.Errorf("sandbox keys count = %d, want 1", len(sbProfile.Keys))
	}
}

func TestDeleteProfileFile(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()
	cfg.Save()

	// File should exist
	if _, err := os.Stat(ProfilePath(DefaultProfileName)); os.IsNotExist(err) {
		t.Fatal("profile file should exist before delete")
	}

	deleteProfileFile(DefaultProfileName)

	if _, err := os.Stat(ProfilePath(DefaultProfileName)); !os.IsNotExist(err) {
		t.Error("profile file should be deleted")
	}
}

func TestConfigDir_WithEnvOverride(t *testing.T) {
	// Reset any programmatic override
	old := configDirOverride
	configDirOverride = ""
	defer func() { configDirOverride = old }()

	t.Setenv("ACKAGENT_CONFIG_DIR", "/tmp/ackagent-test-dir")
	dir := ConfigDir()
	if dir != "/tmp/ackagent-test-dir" {
		t.Errorf("ConfigDir() = %q, want /tmp/ackagent-test-dir", dir)
	}
}

func TestEffectiveOrgForProfile_NoOrgs(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()
	_, err := cfg.EffectiveOrgForProfile()
	if err != ErrNoOrgs {
		t.Errorf("expected ErrNoOrgs, got: %v", err)
	}
}

func TestEffectiveOrgForProfile_WithOrg(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()
	profile, _ := cfg.GetActiveProfile()
	profile.Orgs = []OrgConfig{
		{OrgID: "org-1", EmojiIndex: 5},
	}

	org, err := cfg.EffectiveOrgForProfile()
	if err != nil {
		t.Fatalf("EffectiveOrgForProfile() error = %v", err)
	}
	if org.OrgID != "org-1" {
		t.Errorf("OrgID = %q, want org-1", org.OrgID)
	}
}

func TestEffectiveOrgForProfile_WithWorkingOrg(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()
	profile, _ := cfg.GetActiveProfile()
	profile.Orgs = []OrgConfig{
		{OrgID: "org-1", EmojiIndex: 5},
		{OrgID: "org-2", EmojiIndex: 10},
	}
	cfg.SetWorkingOrg("org-2")

	org, err := cfg.EffectiveOrgForProfile()
	if err != nil {
		t.Fatalf("EffectiveOrgForProfile() error = %v", err)
	}
	if org.OrgID != "org-2" {
		t.Errorf("OrgID = %q, want org-2", org.OrgID)
	}
}

func TestDeleteProfile_WithUserAccount(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()
	cfg.CreateProfile("todelete", "https://relay.example.com", "https://auth.example.com")
	profile, _ := cfg.GetProfile("todelete")
	profile.UserAccount = &UserAccount{
		UserID:                "user-1",
		TokenRef:              "ackagent://todelete/access-token/user-1",
		RefreshTokenRef:       "ackagent://todelete/refresh-token/user-1",
		IdentityPrivateKeyRef: "ackagent://todelete/identity-private/user-1",
	}
	cfg.Save()

	err := cfg.DeleteProfile("todelete")
	if err != nil {
		t.Fatalf("DeleteProfile() error = %v", err)
	}
	if _, ok := cfg.Profiles["todelete"]; ok {
		t.Error("profile should be deleted from map")
	}
}

func TestDeleteProfile_NotFound(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()
	err := cfg.DeleteProfile("nonexistent")
	if err == nil {
		t.Error("DeleteProfile(nonexistent) should error")
	}
}

func TestRenameProfile_SameName(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()
	err := cfg.RenameProfile(DefaultProfileName, DefaultProfileName)
	if err != nil {
		t.Errorf("RenameProfile to same name should be no-op, got: %v", err)
	}
}

func TestRenameProfile_NotFound(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()
	err := cfg.RenameProfile("nonexistent", "new")
	if err == nil {
		t.Error("RenameProfile(nonexistent) should error")
	}
}

func TestRenameProfile_DuplicateName(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()
	cfg.CreateProfile("other", "https://relay.example.com", "https://auth.example.com")

	err := cfg.RenameProfile(DefaultProfileName, "other")
	if err == nil {
		t.Error("RenameProfile to existing name should error")
	}
}

func TestRenameProfile_WithUserAccount(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()
	profile, _ := cfg.GetActiveProfile()
	profile.UserAccount = &UserAccount{
		UserID:                "user-1",
		TokenRef:              "ackagent://default/access-token/user-1",
		RefreshTokenRef:       "ackagent://default/refresh-token/user-1",
		IdentityPrivateKeyRef: "ackagent://default/identity-private/user-1",
	}
	cfg.Save()

	err := cfg.RenameProfile(DefaultProfileName, "production")
	if err != nil {
		t.Fatalf("RenameProfile() error = %v", err)
	}

	if cfg.ActiveProfile != "production" {
		t.Errorf("ActiveProfile = %q, want production", cfg.ActiveProfile)
	}
	if _, ok := cfg.Profiles["production"]; !ok {
		t.Error("new profile name should exist")
	}
	if _, ok := cfg.Profiles[DefaultProfileName]; ok {
		t.Error("old profile name should not exist")
	}
}

func TestRenameProfile_NonActiveProfile(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()
	cfg.CreateProfile("sandbox", "https://sandbox.example.com", "https://auth.sandbox.example.com")
	cfg.Save()

	err := cfg.RenameProfile("sandbox", "staging")
	if err != nil {
		t.Fatalf("RenameProfile() error = %v", err)
	}

	// Active profile should not change
	if cfg.ActiveProfile != DefaultProfileName {
		t.Errorf("ActiveProfile = %q, should still be %q", cfg.ActiveProfile, DefaultProfileName)
	}
	if _, ok := cfg.Profiles["staging"]; !ok {
		t.Error("new profile name should exist")
	}
}

func TestLoadProfileFile_NotFound(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	_, err := loadProfileFile("nonexistent")
	if err == nil {
		t.Error("loadProfileFile(nonexistent) should error")
	}
}

func TestSaveProfileFile_CreatesDir(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	// Profiles dir shouldn't exist yet
	profile := &ProfileConfig{RelayURL: "https://test.example.com"}
	err := saveProfileFile("test", profile)
	if err != nil {
		t.Fatalf("saveProfileFile() error = %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(ProfilePath("test")); os.IsNotExist(err) {
		t.Error("profile file should exist after save")
	}
}

func TestLoadAllProfiles_SkipsDirectories(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()
	cfg.Save()

	// Create a subdirectory in the profiles dir
	os.MkdirAll(filepath.Join(ProfilesDir(), "subdir"), 0700)

	// Create a non-json file
	os.WriteFile(filepath.Join(ProfilesDir(), "notes.txt"), []byte("hello"), 0600)

	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	// Should only have the default profile, not the subdir or txt file
	if len(loaded.Profiles) != 1 {
		t.Errorf("expected 1 profile, got %d", len(loaded.Profiles))
	}
}

func TestConvenienceAccessors_NoActiveProfile(t *testing.T) {
	cfg := &Config{
		Profiles: map[string]*ProfileConfig{},
	}

	if cfg.RelayURL() != "" {
		t.Error("RelayURL() should return empty with no active profile")
	}
	if cfg.IssuerURL() != "" {
		t.Error("IssuerURL() should return empty with no active profile")
	}
	if cfg.UserAccount() != nil {
		t.Error("UserAccount() should return nil with no active profile")
	}
	if cfg.HookSettings() != nil {
		t.Error("HookSettings() should return nil with no active profile")
	}
	if cfg.IsLoggedIn() {
		t.Error("IsLoggedIn() should return false with no active profile")
	}
	if cfg.NeedsTokenRefresh() {
		t.Error("NeedsTokenRefresh() should return false with no active profile")
	}
}

func TestWorkingProfile(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()
	cfg.CreateProfile("sandbox", "https://sandbox.example.com", "")

	// Without working profile, EffectiveProfile returns ActiveProfile
	if cfg.EffectiveProfile() != DefaultProfileName {
		t.Errorf("EffectiveProfile() = %q, want %q", cfg.EffectiveProfile(), DefaultProfileName)
	}

	// Set working profile
	if err := cfg.SetWorkingProfile("sandbox"); err != nil {
		t.Fatalf("SetWorkingProfile() error = %v", err)
	}
	if cfg.EffectiveProfile() != "sandbox" {
		t.Errorf("EffectiveProfile() = %q, want sandbox", cfg.EffectiveProfile())
	}

	// Setting non-existent working profile should error
	if err := cfg.SetWorkingProfile("nonexistent"); err == nil {
		t.Error("SetWorkingProfile(nonexistent) should error")
	}
}
