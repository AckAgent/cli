package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// setupTestDir creates a temp directory and configures it as the config directory.
// Returns a cleanup function that should be deferred.
func setupTestDir(t *testing.T) func() {
	t.Helper()
	tmpDir := t.TempDir()
	SetConfigDir(tmpDir)
	return func() {
		ResetConfigDir()
	}
}

func TestNewDefault(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()

	if cfg.Version != ConfigVersion {
		t.Errorf("Version = %d, want %d", cfg.Version, ConfigVersion)
	}

	if cfg.DeviceID == "" {
		t.Error("DeviceID is empty")
	}

	if cfg.DeviceName == "" {
		t.Error("DeviceName is empty")
	}

	if cfg.ActiveProfile != DefaultProfileName {
		t.Errorf("ActiveProfile = %s, want %s", cfg.ActiveProfile, DefaultProfileName)
	}

	if len(cfg.Profiles) != 1 {
		t.Errorf("Profiles count = %d, want 1", len(cfg.Profiles))
	}

	if cfg.IsLoggedIn() {
		t.Error("New config should not be logged in")
	}
}

func TestSaveLoad(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	// Create a config
	cfg := NewDefault()
	profile, _ := cfg.GetActiveProfile()
	profile.RelayURL = "http://test.example.com"
	cfg.AddKey(KeyMetadata{
		IOSKeyID:  "key-1",
		Label:     "Test Key",
		PublicKey: []byte{0x04, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56},
		Algorithm: "ecdsa-sha2-nistp256",
		CreatedAt: time.Now(),
	})

	// Save using the proper Save method (now uses temp dir)
	if err := cfg.Save(); err != nil {
		t.Fatalf("Failed to save config: %v", err)
	}

	// Verify the config file was written
	if _, err := os.Stat(ConfigPath()); os.IsNotExist(err) {
		t.Error("Config file was not created")
	}

	// Verify the profile file was written
	if _, err := os.Stat(ProfilePath(DefaultProfileName)); os.IsNotExist(err) {
		t.Error("Profile file was not created")
	}

	// Load config back using Load()
	loadedCfg, err := Load()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify the data
	loadedProfile, err := loadedCfg.GetActiveProfile()
	if err != nil {
		t.Fatalf("Failed to get profile: %v", err)
	}
	if loadedProfile.RelayURL != "http://test.example.com" {
		t.Errorf("RelayURL = %s, want http://test.example.com", loadedProfile.RelayURL)
	}
	if len(loadedProfile.Keys) != 1 {
		t.Errorf("Keys count = %d, want 1", len(loadedProfile.Keys))
	}
}

func TestIsLoggedIn(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()

	if cfg.IsLoggedIn() {
		t.Error("New config should not be logged in")
	}

	profile, _ := cfg.GetActiveProfile()
	profile.UserAccount = &UserAccount{
		UserID: "user-123",
	}

	if cfg.IsLoggedIn() {
		t.Error("UserAccount without SAS verified should not be logged in")
	}

	profile.UserAccount.SASVerified = true

	if cfg.IsLoggedIn() {
		t.Error("UserAccount without devices should not be logged in")
	}

	profile.UserAccount.Devices = []UserDevice{
		{ApproverId: "test-approver-uuid", PublicKey: []byte("pubkey")},
	}

	if !cfg.IsLoggedIn() {
		t.Error("Config with SAS verified and devices should be logged in")
	}
}

func TestFindKey(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()
	cfg.AddKey(KeyMetadata{
		IOSKeyID:  "key-uuid-123",
		PublicKey: []byte{0xab, 0xcd, 0xef, 0x12, 0x34, 0x56},
		Label:     "My Key",
	})

	tests := []struct {
		query   string
		wantID  string
		wantErr bool
	}{
		{"key-uuid-123", "key-uuid-123", false},
		{"abcdef123456", "key-uuid-123", false},
		{"My Key", "key-uuid-123", false},
		{"123456", "key-uuid-123", false}, // suffix match
		{"nonexistent", "", true},
	}

	for _, tt := range tests {
		key, err := cfg.FindKey(tt.query)
		if tt.wantErr {
			if err == nil {
				t.Errorf("FindKey(%q) expected error", tt.query)
			}
		} else {
			if err != nil {
				t.Errorf("FindKey(%q) unexpected error: %v", tt.query, err)
			} else if key.IOSKeyID != tt.wantID {
				t.Errorf("FindKey(%q) = %s, want %s", tt.query, key.IOSKeyID, tt.wantID)
			}
		}
	}
}

func TestAddKey(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()

	key1 := KeyMetadata{IOSKeyID: "key-1", Label: "Key 1"}
	key2 := KeyMetadata{IOSKeyID: "key-2", Label: "Key 2"}

	cfg.AddKey(key1)
	keys := cfg.Keys()
	if len(keys) != 1 {
		t.Errorf("Keys count = %d, want 1", len(keys))
	}

	cfg.AddKey(key2)
	keys = cfg.Keys()
	if len(keys) != 2 {
		t.Errorf("Keys count = %d, want 2", len(keys))
	}

	// Update existing key
	key1Updated := KeyMetadata{IOSKeyID: "key-1", Label: "Key 1 Updated"}
	cfg.AddKey(key1Updated)
	keys = cfg.Keys()
	if len(keys) != 2 {
		t.Errorf("Keys count after update = %d, want 2", len(keys))
	}

	found, _ := cfg.FindKey("key-1")
	if found.Label != "Key 1 Updated" {
		t.Errorf("Key label = %s, want Key 1 Updated", found.Label)
	}
}

func TestAddKey_EmptyIOSKeyID_DoesNotOverwrite(t *testing.T) {
	// Regression: two GPG keys with IOSKeyID="" should coexist, not overwrite
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()

	key1 := KeyMetadata{
		IOSKeyID:  "",
		Label:     "Key 1 <key1@test.com>",
		PublicKey: []byte{0x01, 0x02, 0x03},
		Purpose:   KeyPurposeGPG,
	}
	key2 := KeyMetadata{
		IOSKeyID:  "",
		Label:     "Key 2 <key2@test.com>",
		PublicKey: []byte{0x04, 0x05, 0x06},
		Purpose:   KeyPurposeGPG,
	}

	cfg.AddKey(key1)
	cfg.AddKey(key2)
	keys := cfg.Keys()
	if len(keys) != 2 {
		t.Errorf("Keys count = %d, want 2 (two distinct empty-IOSKeyID keys)", len(keys))
	}
}

func TestAddKey_EmptyIOSKeyID_UpdatesBySamePublicKey(t *testing.T) {
	// Update case: same public key + purpose with empty IOSKeyID should update in place
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()
	pubKey := []byte{0x01, 0x02, 0x03}

	key1 := KeyMetadata{IOSKeyID: "", Label: "Old Label", PublicKey: pubKey, Purpose: KeyPurposeGPG}
	cfg.AddKey(key1)

	key1Updated := KeyMetadata{IOSKeyID: "", Label: "New Label", PublicKey: pubKey, Purpose: KeyPurposeGPG}
	cfg.AddKey(key1Updated)

	keys := cfg.Keys()
	if len(keys) != 1 {
		t.Errorf("Keys count = %d, want 1 (same key updated)", len(keys))
	}
	if keys[0].Label != "New Label" {
		t.Errorf("Label = %s, want New Label", keys[0].Label)
	}
}

func TestAddKey_NonEmptyIOSKeyID_StillDeduplicates(t *testing.T) {
	// Existing behavior preserved: keys with matching non-empty IOSKeyID update
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()
	cfg.AddKey(KeyMetadata{IOSKeyID: "abc", Label: "Old"})
	cfg.AddKey(KeyMetadata{IOSKeyID: "abc", Label: "New"})

	keys := cfg.Keys()
	if len(keys) != 1 {
		t.Errorf("Keys count = %d, want 1", len(keys))
	}
	if keys[0].Label != "New" {
		t.Errorf("Label = %s, want New", keys[0].Label)
	}
}

func TestRemoveKey(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()
	cfg.AddKey(KeyMetadata{IOSKeyID: "key-1"})
	cfg.AddKey(KeyMetadata{IOSKeyID: "key-2"})

	if !cfg.RemoveKey("key-1") {
		t.Error("RemoveKey should return true for existing key")
	}

	keys := cfg.Keys()
	if len(keys) != 1 {
		t.Errorf("Keys count = %d, want 1", len(keys))
	}

	if cfg.RemoveKey("key-1") {
		t.Error("RemoveKey should return false for non-existing key")
	}
}

func TestConfigDir(t *testing.T) {
	dir := ConfigDir()
	if dir == "" {
		t.Error("ConfigDir returned empty string")
	}

	// Should contain the app ID
	if filepath.Base(dir) != AppID {
		t.Errorf("ConfigDir base = %s, want %s", filepath.Base(dir), AppID)
	}
}

func TestConfigPath(t *testing.T) {
	path := ConfigPath()
	if path == "" {
		t.Error("ConfigPath returned empty string")
	}

	if filepath.Base(path) != "config.json" {
		t.Errorf("ConfigPath base = %s, want config.json", filepath.Base(path))
	}
}

func TestListProfiles(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()

	profiles := cfg.ListProfiles()
	if len(profiles) != 1 {
		t.Errorf("ListProfiles count = %d, want 1", len(profiles))
	}
	if profiles[0] != DefaultProfileName {
		t.Errorf("ListProfiles[0] = %s, want %s", profiles[0], DefaultProfileName)
	}

	// Add more profiles
	cfg.CreateProfile("sandbox", "https://sandbox.example.com", "https://auth.sandbox.example.com")
	cfg.CreateProfile("production", "https://prod.example.com", "https://auth.prod.example.com")

	profiles = cfg.ListProfiles()
	if len(profiles) != 3 {
		t.Errorf("ListProfiles count = %d, want 3", len(profiles))
	}
}

func TestSetActiveProfile(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()
	cfg.CreateProfile("sandbox", "https://sandbox.example.com", "https://auth.sandbox.example.com")

	if err := cfg.SetActiveProfile("sandbox"); err != nil {
		t.Errorf("SetActiveProfile failed: %v", err)
	}

	if cfg.ActiveProfile != "sandbox" {
		t.Errorf("ActiveProfile = %s, want sandbox", cfg.ActiveProfile)
	}

	// Try non-existent profile
	if err := cfg.SetActiveProfile("nonexistent"); err == nil {
		t.Error("SetActiveProfile should fail for non-existent profile")
	}
}

func TestCreateProfile(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()

	if err := cfg.CreateProfile("sandbox", "https://sandbox.example.com", "https://auth.sandbox.example.com"); err != nil {
		t.Errorf("CreateProfile failed: %v", err)
	}

	profile, err := cfg.GetProfile("sandbox")
	if err != nil {
		t.Errorf("GetProfile failed: %v", err)
	}
	if profile.RelayURL != "https://sandbox.example.com" {
		t.Errorf("RelayURL = %s, want https://sandbox.example.com", profile.RelayURL)
	}

	// Creating duplicate should fail
	if err := cfg.CreateProfile("sandbox", "https://other.example.com", "https://auth.other.example.com"); err == nil {
		t.Error("CreateProfile should fail for duplicate name")
	}
}

func TestDeleteProfile(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()
	cfg.CreateProfile("sandbox", "https://sandbox.example.com", "https://auth.sandbox.example.com")
	cfg.SetActiveProfile("sandbox")

	if err := cfg.DeleteProfile("sandbox"); err != nil {
		t.Errorf("DeleteProfile failed: %v", err)
	}

	// Active should have switched
	if cfg.ActiveProfile == "sandbox" {
		t.Error("Active profile should have switched after deletion")
	}

	// Profile should be gone
	if _, err := cfg.GetProfile("sandbox"); err == nil {
		t.Error("Deleted profile should not be found")
	}

	// Can't delete last profile
	if err := cfg.DeleteProfile(cfg.ActiveProfile); err != ErrCannotDeleteLast {
		t.Errorf("DeleteProfile should fail with ErrCannotDeleteLast, got: %v", err)
	}
}

func TestRenameProfile(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()

	if err := cfg.RenameProfile(DefaultProfileName, "production"); err != nil {
		t.Errorf("RenameProfile failed: %v", err)
	}

	if cfg.ActiveProfile != "production" {
		t.Errorf("ActiveProfile = %s, want production", cfg.ActiveProfile)
	}

	if _, err := cfg.GetProfile(DefaultProfileName); err == nil {
		t.Error("Old profile name should not exist after rename")
	}

	if _, err := cfg.GetProfile("production"); err != nil {
		t.Errorf("New profile name should exist: %v", err)
	}
}

func TestKeysForPurpose(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()

	// Add keys with different purposes
	cfg.AddKey(KeyMetadata{IOSKeyID: "ssh-1", Label: "SSH Key 1", Purpose: KeyPurposeSSH})
	cfg.AddKey(KeyMetadata{IOSKeyID: "ssh-2", Label: "SSH Key 2", Purpose: KeyPurposeSSH})
	cfg.AddKey(KeyMetadata{IOSKeyID: "gpg-1", Label: "GPG Key 1", Purpose: KeyPurposeGPG})
	cfg.AddKey(KeyMetadata{IOSKeyID: "age-1", Label: "Age Key 1", Purpose: KeyPurposeAge})
	cfg.AddKey(KeyMetadata{IOSKeyID: "age-2", Label: "Age Key 2", Purpose: KeyPurposeAge})
	cfg.AddKey(KeyMetadata{IOSKeyID: "age-3", Label: "Age Key 3", Purpose: KeyPurposeAge})

	tests := []struct {
		purpose   KeyPurpose
		wantCount int
	}{
		{KeyPurposeSSH, 2},
		{KeyPurposeGPG, 1},
		{KeyPurposeAge, 3},
		{"unknown", 0},
	}

	for _, tt := range tests {
		keys := cfg.KeysForPurpose(tt.purpose)
		if len(keys) != tt.wantCount {
			t.Errorf("KeysForPurpose(%s) count = %d, want %d", tt.purpose, len(keys), tt.wantCount)
		}

		// Verify all returned keys have the correct purpose
		for _, k := range keys {
			if k.Purpose != tt.purpose {
				t.Errorf("KeysForPurpose(%s) returned key with purpose %s", tt.purpose, k.Purpose)
			}
		}
	}
}

func TestIsLabelUnique(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()

	// Add some keys
	cfg.AddKey(KeyMetadata{IOSKeyID: "ssh-1", Label: "mykey", Purpose: KeyPurposeSSH})
	cfg.AddKey(KeyMetadata{IOSKeyID: "gpg-1", Label: "Test User <test@example.com>", Purpose: KeyPurposeGPG})
	cfg.AddKey(KeyMetadata{IOSKeyID: "age-1", Label: "ackagent-age", Purpose: KeyPurposeAge})

	tests := []struct {
		purpose    KeyPurpose
		label      string
		wantUnique bool
	}{
		// Existing labels should not be unique for their purpose
		{KeyPurposeSSH, "mykey", false},
		{KeyPurposeGPG, "Test User <test@example.com>", false},
		{KeyPurposeAge, "ackagent-age", false},
		// Same label but different purpose should be unique
		{KeyPurposeGPG, "mykey", true},
		{KeyPurposeAge, "mykey", true},
		{KeyPurposeSSH, "ackagent-age", true},
		// New labels should be unique
		{KeyPurposeSSH, "newkey", true},
		{KeyPurposeGPG, "Another User <another@example.com>", true},
		{KeyPurposeAge, "personal-age", true},
	}

	for _, tt := range tests {
		isUnique := cfg.IsLabelUnique(tt.purpose, tt.label)
		if isUnique != tt.wantUnique {
			t.Errorf("IsLabelUnique(%s, %q) = %v, want %v", tt.purpose, tt.label, isUnique, tt.wantUnique)
		}
	}
}

func TestMultipleKeysPerPurpose(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()

	// Add multiple SSH keys
	cfg.AddKey(KeyMetadata{IOSKeyID: "ssh-1", Label: "work", Purpose: KeyPurposeSSH, PublicKey: []byte{0xab, 0xcd}})
	cfg.AddKey(KeyMetadata{IOSKeyID: "ssh-2", Label: "personal", Purpose: KeyPurposeSSH, PublicKey: []byte{0xde, 0xf0}})
	cfg.AddKey(KeyMetadata{IOSKeyID: "ssh-3", Label: "backup", Purpose: KeyPurposeSSH, PublicKey: []byte{0x12, 0x34}})

	// Verify we can list all
	sshKeys := cfg.KeysForPurpose(KeyPurposeSSH)
	if len(sshKeys) != 3 {
		t.Errorf("Expected 3 SSH keys, got %d", len(sshKeys))
	}

	// Verify FindKeyByPurpose returns first matching key
	firstKey := cfg.FindKeyByPurpose(KeyPurposeSSH)
	if firstKey == nil {
		t.Error("FindKeyByPurpose returned nil")
	} else if firstKey.IOSKeyID != "ssh-1" {
		t.Errorf("FindKeyByPurpose returned %s, expected ssh-1", firstKey.IOSKeyID)
	}

	// Verify we can find specific keys
	key, err := cfg.FindKey("personal")
	if err != nil {
		t.Errorf("FindKey(personal) failed: %v", err)
	} else if key.IOSKeyID != "ssh-2" {
		t.Errorf("FindKey(personal) returned %s, expected ssh-2", key.IOSKeyID)
	}

	// Verify label uniqueness is enforced
	if cfg.IsLabelUnique(KeyPurposeSSH, "work") {
		t.Error("IsLabelUnique should return false for existing label 'work'")
	}
	if !cfg.IsLabelUnique(KeyPurposeSSH, "new-key") {
		t.Error("IsLabelUnique should return true for new label 'new-key'")
	}
}

func TestOrgConfigEmoji(t *testing.T) {
	org := OrgConfig{
		OrgID:      "org-123",
		EmojiIndex: 0,
	}

	words := org.EmojiWords()
	if words == "" {
		t.Error("EmojiWords() returned empty string")
	}

	emojis := org.Emojis()
	if emojis == "" {
		t.Error("Emojis() returned empty string")
	}

	// Two-emoji index
	org.EmojiIndex = 256
	words = org.EmojiWords()
	if words == "" {
		t.Error("EmojiWords() for index 256 returned empty string")
	}
}

func TestOrgConfigDisplayName(t *testing.T) {
	org := OrgConfig{
		OrgID:      "org-123",
		EmojiIndex: 42,
	}

	// Without local name, should use emoji words
	name := org.DisplayName()
	if name == "" {
		t.Error("DisplayName() returned empty for org without local name")
	}
	if name != org.EmojiWords() {
		t.Errorf("DisplayName() = %q, want %q (emoji words)", name, org.EmojiWords())
	}

	// With local name, should use local name
	org.LocalName = "My Corp"
	name = org.DisplayName()
	if name != "My Corp" {
		t.Errorf("DisplayName() = %q, want %q", name, "My Corp")
	}
}

func TestResolveOrgByUUID(t *testing.T) {
	p := &ProfileConfig{
		Orgs: []OrgConfig{
			{OrgID: "org-aaa", EmojiIndex: 0},
			{OrgID: "org-bbb", EmojiIndex: 1, LocalName: "Acme Corp"},
		},
	}

	org, err := p.ResolveOrg("org-bbb")
	if err != nil {
		t.Fatalf("ResolveOrg by UUID failed: %v", err)
	}
	if org.OrgID != "org-bbb" {
		t.Errorf("ResolveOrg returned wrong org: %s", org.OrgID)
	}
}

func TestResolveOrgByLocalName(t *testing.T) {
	p := &ProfileConfig{
		Orgs: []OrgConfig{
			{OrgID: "org-aaa", EmojiIndex: 0},
			{OrgID: "org-bbb", EmojiIndex: 1, LocalName: "Acme Corp"},
		},
	}

	// Case-insensitive match
	org, err := p.ResolveOrg("acme corp")
	if err != nil {
		t.Fatalf("ResolveOrg by local name failed: %v", err)
	}
	if org.OrgID != "org-bbb" {
		t.Errorf("ResolveOrg returned wrong org: %s", org.OrgID)
	}
}

func TestResolveOrgByEmojiWords(t *testing.T) {
	p := &ProfileConfig{
		Orgs: []OrgConfig{
			{OrgID: "org-aaa", EmojiIndex: 42},
		},
	}

	emojiWords := p.Orgs[0].EmojiWords()
	org, err := p.ResolveOrg(emojiWords)
	if err != nil {
		t.Fatalf("ResolveOrg by emoji words failed: %v", err)
	}
	if org.OrgID != "org-aaa" {
		t.Errorf("ResolveOrg returned wrong org: %s", org.OrgID)
	}
}

func TestResolveOrgNotFound(t *testing.T) {
	p := &ProfileConfig{
		Orgs: []OrgConfig{
			{OrgID: "org-aaa", EmojiIndex: 0},
		},
	}

	_, err := p.ResolveOrg("nonexistent")
	if err == nil {
		t.Error("ResolveOrg should fail for nonexistent org")
	}
}

func TestResolveOrgNoOrgs(t *testing.T) {
	p := &ProfileConfig{}

	_, err := p.ResolveOrg("anything")
	if err != ErrNoOrgs {
		t.Errorf("ResolveOrg should return ErrNoOrgs, got: %v", err)
	}
}

func TestEffectiveOrgOverride(t *testing.T) {
	p := &ProfileConfig{
		Orgs: []OrgConfig{
			{OrgID: "org-aaa", EmojiIndex: 0, LocalName: "Alpha"},
			{OrgID: "org-bbb", EmojiIndex: 1, LocalName: "Beta"},
		},
		DefaultOrgID: "org-aaa",
	}

	// Override should win over default
	org, err := p.EffectiveOrg("org-bbb")
	if err != nil {
		t.Fatalf("EffectiveOrg with override failed: %v", err)
	}
	if org.OrgID != "org-bbb" {
		t.Errorf("EffectiveOrg returned %s, want org-bbb", org.OrgID)
	}
}

func TestEffectiveOrgDefault(t *testing.T) {
	p := &ProfileConfig{
		Orgs: []OrgConfig{
			{OrgID: "org-aaa", EmojiIndex: 0},
			{OrgID: "org-bbb", EmojiIndex: 1},
		},
		DefaultOrgID: "org-bbb",
	}

	// No override, should use default
	org, err := p.EffectiveOrg("")
	if err != nil {
		t.Fatalf("EffectiveOrg with default failed: %v", err)
	}
	if org.OrgID != "org-bbb" {
		t.Errorf("EffectiveOrg returned %s, want org-bbb", org.OrgID)
	}
}

func TestEffectiveOrgSingleAutoSelect(t *testing.T) {
	p := &ProfileConfig{
		Orgs: []OrgConfig{
			{OrgID: "org-only", EmojiIndex: 5},
		},
	}

	// Single org, no default set: auto-select
	org, err := p.EffectiveOrg("")
	if err != nil {
		t.Fatalf("EffectiveOrg single org auto-select failed: %v", err)
	}
	if org.OrgID != "org-only" {
		t.Errorf("EffectiveOrg returned %s, want org-only", org.OrgID)
	}
}

func TestEffectiveOrgMultipleRequiresFlag(t *testing.T) {
	p := &ProfileConfig{
		Orgs: []OrgConfig{
			{OrgID: "org-aaa", EmojiIndex: 0},
			{OrgID: "org-bbb", EmojiIndex: 1},
		},
		// No default set
	}

	_, err := p.EffectiveOrg("")
	if err != ErrOrgRequired {
		t.Errorf("EffectiveOrg should return ErrOrgRequired with multiple orgs and no default, got: %v", err)
	}
}

func TestEffectiveOrgNoOrgs(t *testing.T) {
	p := &ProfileConfig{}

	_, err := p.EffectiveOrg("")
	if err != ErrNoOrgs {
		t.Errorf("EffectiveOrg should return ErrNoOrgs, got: %v", err)
	}
}

func TestConfigV4Serialization(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()
	p, _ := cfg.GetActiveProfile()

	// Add orgs with keys
	p.Orgs = []OrgConfig{
		{
			OrgID:      "org-aaa",
			EmojiIndex: 42,
			LocalName:  "Test Org",
			Keys: []KeyMetadata{
				{IOSKeyID: "key-1", Label: "SSH Key", Purpose: KeyPurposeSSH},
			},
		},
		{
			OrgID:      "org-bbb",
			EmojiIndex: 256,
			Keys: []KeyMetadata{
				{IOSKeyID: "key-2", Label: "GPG Key", Purpose: KeyPurposeGPG},
			},
		},
	}
	p.DefaultOrgID = "org-aaa"

	// Save and reload
	if err := cfg.Save(); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	loadedP, err := loaded.GetActiveProfile()
	if err != nil {
		t.Fatalf("GetActiveProfile failed: %v", err)
	}

	if len(loadedP.Orgs) != 2 {
		t.Errorf("Orgs count = %d, want 2", len(loadedP.Orgs))
	}
	if loadedP.DefaultOrgID != "org-aaa" {
		t.Errorf("DefaultOrgID = %s, want org-aaa", loadedP.DefaultOrgID)
	}

	// Verify org details survived round-trip
	org := loadedP.FindOrg("org-aaa")
	if org == nil {
		t.Fatal("FindOrg(org-aaa) returned nil")
	}
	if org.LocalName != "Test Org" {
		t.Errorf("LocalName = %s, want Test Org", org.LocalName)
	}
	if org.EmojiIndex != 42 {
		t.Errorf("EmojiIndex = %d, want 42", org.EmojiIndex)
	}
	if len(org.Keys) != 1 {
		t.Errorf("Keys count = %d, want 1", len(org.Keys))
	}
}

func TestConfigV4JSONStructure(t *testing.T) {
	// Verify the JSON output has expected fields
	p := ProfileConfig{
		RelayURL: "https://relay.example.com",
		Orgs: []OrgConfig{
			{OrgID: "org-1", EmojiIndex: 10},
		},
		DefaultOrgID: "org-1",
	}

	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if _, ok := raw["orgs"]; !ok {
		t.Error("JSON should contain 'orgs' field")
	}
	if _, ok := raw["default_org_id"]; !ok {
		t.Error("JSON should contain 'default_org_id' field")
	}
}

func TestAddOrg(t *testing.T) {
	p := &ProfileConfig{}

	// Add new org
	p.AddOrg(OrgConfig{OrgID: "org-1", EmojiIndex: 5})
	if len(p.Orgs) != 1 {
		t.Errorf("Orgs count = %d, want 1", len(p.Orgs))
	}

	// Add another
	p.AddOrg(OrgConfig{OrgID: "org-2", EmojiIndex: 10})
	if len(p.Orgs) != 2 {
		t.Errorf("Orgs count = %d, want 2", len(p.Orgs))
	}

	// Update existing
	p.AddOrg(OrgConfig{OrgID: "org-1", EmojiIndex: 99, LocalName: "Updated"})
	if len(p.Orgs) != 2 {
		t.Errorf("Orgs count after update = %d, want 2", len(p.Orgs))
	}
	org := p.FindOrg("org-1")
	if org == nil {
		t.Fatal("FindOrg returned nil after update")
	}
	if org.EmojiIndex != 99 {
		t.Errorf("EmojiIndex = %d, want 99", org.EmojiIndex)
	}
	if org.LocalName != "Updated" {
		t.Errorf("LocalName = %s, want Updated", org.LocalName)
	}
}

func TestFindKeyAcrossProfilesAndOrgs(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()
	p, _ := cfg.GetActiveProfile()

	// Add profile-level key
	p.Keys = []KeyMetadata{
		{IOSKeyID: "profile-key", Label: "Profile Key"},
	}

	// Add org-level key
	p.Orgs = []OrgConfig{
		{
			OrgID:      "org-1",
			EmojiIndex: 5,
			Keys: []KeyMetadata{
				{IOSKeyID: "org-key", Label: "Org Key"},
			},
		},
	}

	// Find profile-level key
	key, profileName, err := cfg.FindKeyAcrossProfilesAndOrgs("profile-key")
	if err != nil {
		t.Fatalf("FindKeyAcrossProfilesAndOrgs(profile-key) failed: %v", err)
	}
	if key.Label != "Profile Key" {
		t.Errorf("Label = %s, want Profile Key", key.Label)
	}
	if profileName != DefaultProfileName {
		t.Errorf("Profile = %s, want %s", profileName, DefaultProfileName)
	}

	// Find org-level key
	key, profileName, err = cfg.FindKeyAcrossProfilesAndOrgs("org-key")
	if err != nil {
		t.Fatalf("FindKeyAcrossProfilesAndOrgs(org-key) failed: %v", err)
	}
	if key.Label != "Org Key" {
		t.Errorf("Label = %s, want Org Key", key.Label)
	}

	// Not found
	_, _, err = cfg.FindKeyAcrossProfilesAndOrgs("nonexistent")
	if err != ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound, got: %v", err)
	}
}

func TestOrgAwareKeyAccessors(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()
	p, _ := cfg.GetActiveProfile()

	// Set up orgs with keys
	p.Orgs = []OrgConfig{
		{
			OrgID:      "org-1",
			EmojiIndex: 5,
			Keys: []KeyMetadata{
				{IOSKeyID: "ssh-1", Label: "SSH Key", Purpose: KeyPurposeSSH, PublicKey: []byte{0x01, 0x02}},
				{IOSKeyID: "gpg-1", Label: "GPG Key", Purpose: KeyPurposeGPG, PublicKey: []byte{0x03, 0x04}},
			},
		},
		{
			OrgID:      "org-2",
			EmojiIndex: 10,
			Keys: []KeyMetadata{
				{IOSKeyID: "ssh-2", Label: "SSH Key 2", Purpose: KeyPurposeSSH, PublicKey: []byte{0x05, 0x06}},
			},
		},
	}
	p.DefaultOrgID = "org-1"

	// Keys() should return org-1 keys (default)
	keys := cfg.Keys()
	if len(keys) != 2 {
		t.Errorf("Keys() count = %d, want 2", len(keys))
	}

	// FindKey should search within org-1
	key, err := cfg.FindKey("SSH Key")
	if err != nil {
		t.Fatalf("FindKey failed: %v", err)
	}
	if key.IOSKeyID != "ssh-1" {
		t.Errorf("FindKey returned %s, want ssh-1", key.IOSKeyID)
	}

	// FindKeyByPurpose should search within org-1
	gpgKey := cfg.FindKeyByPurpose(KeyPurposeGPG)
	if gpgKey == nil {
		t.Fatal("FindKeyByPurpose(gpg) returned nil")
	}
	if gpgKey.IOSKeyID != "gpg-1" {
		t.Errorf("FindKeyByPurpose returned %s, want gpg-1", gpgKey.IOSKeyID)
	}

	// KeysForPurpose should filter within org-1
	sshKeys := cfg.KeysForPurpose(KeyPurposeSSH)
	if len(sshKeys) != 1 {
		t.Errorf("KeysForPurpose(ssh) count = %d, want 1", len(sshKeys))
	}

	// IsLabelUnique should check within org-1
	if cfg.IsLabelUnique(KeyPurposeSSH, "SSH Key") {
		t.Error("IsLabelUnique should return false for existing label in org-1")
	}
	if !cfg.IsLabelUnique(KeyPurposeSSH, "new-key") {
		t.Error("IsLabelUnique should return true for new label")
	}

	// Switch to org-2 via working org
	cfg.SetWorkingOrg("org-2")
	keys = cfg.Keys()
	if len(keys) != 1 {
		t.Errorf("Keys() with org-2 override count = %d, want 1", len(keys))
	}
	if keys[0].IOSKeyID != "ssh-2" {
		t.Errorf("Keys()[0] = %s, want ssh-2", keys[0].IOSKeyID)
	}

	// AddKey should add to org-2
	cfg.AddKey(KeyMetadata{IOSKeyID: "age-1", Label: "Age Key", Purpose: KeyPurposeAge})
	keys = cfg.Keys()
	if len(keys) != 2 {
		t.Errorf("Keys() after add = %d, want 2", len(keys))
	}

	// RemoveKey should remove from org-2
	if !cfg.RemoveKey("age-1") {
		t.Error("RemoveKey should return true")
	}
	keys = cfg.Keys()
	if len(keys) != 1 {
		t.Errorf("Keys() after remove = %d, want 1", len(keys))
	}
}
