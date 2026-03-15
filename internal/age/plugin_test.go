package age

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ackagent/cli/internal/shared/config"
)

// createTestConfig creates a test config with the given keys in the active profile
func createTestConfig(keys []config.KeyMetadata) *config.Config {
	profile := &config.ProfileConfig{
		Keys: keys,
	}

	cfg := &config.Config{
		ActiveProfile: "test",
		Profiles: map[string]*config.ProfileConfig{
			"test": profile,
		},
	}

	return cfg
}

func TestNewPlugin(t *testing.T) {
	p := NewPlugin()
	if p == nil {
		t.Error("NewPlugin() returned nil")
	}
}

func TestPluginName(t *testing.T) {
	p := NewPlugin()
	name := p.Name()

	if name != "ackagent" {
		t.Errorf("Plugin.Name() = %v, want 'ackagent'", name)
	}
}

func TestPluginRecipientV1(t *testing.T) {
	p := NewPlugin()

	// Create a valid recipient string
	testKey, _ := hex.DecodeString("e6eb32e9739a52ef8e2c95aa9f1a7f2fddc8dd9fa79eef22c7a0d0f4e52f3d1a")
	validRecipient := &Recipient{PublicKey: testKey}
	validString := validRecipient.String()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "valid recipient",
			input:   validString,
			wantErr: false,
		},
		{
			name:    "wrong prefix",
			input:   "age1notackagent" + strings.Repeat("q", 52),
			wantErr: true,
		},
		{
			name:    "invalid encoding",
			input:   RecipientPrefix + "!!!invalid!!!",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recipient, err := p.RecipientV1(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("RecipientV1() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && recipient == nil {
				t.Error("RecipientV1() returned nil recipient")
			}
		})
	}
}

func TestPluginIdentityV1(t *testing.T) {
	// This test is limited because IdentityV1 requires config loading and login state
	// Full testing requires integration tests with mocked config

	p := NewPlugin()

	// Test with obviously invalid identity
	_, err := p.IdentityV1("invalid-identity")
	if err == nil {
		t.Error("IdentityV1() should fail for invalid identity")
	}

	// Test with wrong prefix
	_, err = p.IdentityV1("AGE-PLUGIN-WRONG-1abc123")
	if err == nil {
		t.Error("IdentityV1() should fail for wrong prefix")
	}
}

func TestGetRecipient(t *testing.T) {
	// Test with mock config that has an age key
	testKey, _ := hex.DecodeString("e6eb32e9739a52ef8e2c95aa9f1a7f2fddc8dd9fa79eef22c7a0d0f4e52f3d1a")
	expectedRecipient := (&Recipient{PublicKey: testKey}).String()

	cfg := createTestConfig([]config.KeyMetadata{
		{
			PublicKey:    testKey,
			Purpose:      config.KeyPurposeAge,
			AgeRecipient: expectedRecipient,
		},
	})

	recipient, err := GetRecipient(cfg)
	if err != nil {
		t.Fatalf("GetRecipient() error = %v", err)
	}

	if recipient != expectedRecipient {
		t.Errorf("GetRecipient() = %v, want %v", recipient, expectedRecipient)
	}
}

func TestGetRecipientNoAgeKey(t *testing.T) {
	cfg := createTestConfig([]config.KeyMetadata{
		{
			PublicKey: []byte{0xcc, 0xdd, 0xee, 0x00, 0x11, 0x22},
			Purpose:   "gpg", // Not age
		},
	})

	_, err := GetRecipient(cfg)
	if err == nil {
		t.Error("GetRecipient() should fail when no age key exists")
	}

	if !strings.Contains(err.Error(), "no age key") {
		t.Errorf("GetRecipient() error = %v, should mention no age key", err)
	}
}

func TestGetRecipientReconstructsFromPublicKey(t *testing.T) {
	// Test that recipient is reconstructed from public key if AgeRecipient is empty
	testKey, _ := hex.DecodeString("e6eb32e9739a52ef8e2c95aa9f1a7f2fddc8dd9fa79eef22c7a0d0f4e52f3d1a")

	cfg := createTestConfig([]config.KeyMetadata{
		{
			PublicKey:    testKey,
			Purpose:      config.KeyPurposeAge,
			AgeRecipient: "", // Empty - should be reconstructed
		},
	})

	recipient, err := GetRecipient(cfg)
	if err != nil {
		t.Fatalf("GetRecipient() error = %v", err)
	}

	// Should start with the correct prefix
	if !strings.HasPrefix(recipient, RecipientPrefix) {
		t.Errorf("GetRecipient() = %v, should start with %v", recipient, RecipientPrefix)
	}

	// Verify roundtrip
	parsed, err := ParseRecipient(recipient)
	if err != nil {
		t.Fatalf("ParseRecipient() error = %v", err)
	}

	if !bytes.Equal(parsed.PublicKey, testKey) {
		t.Errorf("reconstructed recipient has wrong key")
	}
}

func TestGetIdentity(t *testing.T) {
	testKey, _ := hex.DecodeString("e6eb32e9739a52ef8e2c95aa9f1a7f2fddc8dd9fa79eef22c7a0d0f4e52f3d1a")

	cfg := createTestConfig([]config.KeyMetadata{
		{
			PublicKey: testKey,
			Purpose:   config.KeyPurposeAge,
		},
	})

	identity, err := GetIdentity(cfg)
	if err != nil {
		t.Fatalf("GetIdentity() error = %v", err)
	}

	// Should start with identity prefix
	if !strings.HasPrefix(identity, IdentityPrefix) {
		t.Errorf("GetIdentity() = %v, should start with %v", identity, IdentityPrefix)
	}

	// Should be uppercase
	if identity != strings.ToUpper(identity) {
		t.Errorf("GetIdentity() should be uppercase: %v", identity)
	}
}

func TestGetIdentityNoAgeKey(t *testing.T) {
	cfg := createTestConfig([]config.KeyMetadata{}) // No keys

	_, err := GetIdentity(cfg)
	if err == nil {
		t.Error("GetIdentity() should fail when no age key exists")
	}
}

func TestGetIdentityFilePath(t *testing.T) {
	path := GetIdentityFilePath()

	// Should contain expected file name
	if !strings.HasSuffix(path, "age-identity.txt") {
		t.Errorf("GetIdentityFilePath() = %v, should end with 'age-identity.txt'", path)
	}

	// Should be in config directory
	configDir := config.ConfigDir()
	if !strings.HasPrefix(path, configDir) {
		t.Errorf("GetIdentityFilePath() = %v, should be in config dir %v", path, configDir)
	}
}

func TestWriteIdentityFile(t *testing.T) {
	// Create a temp directory for testing
	tempDir := t.TempDir()

	// Override config dir temporarily
	origConfigDir := os.Getenv("ACKAGENT_CONFIG_DIR")
	os.Setenv("ACKAGENT_CONFIG_DIR", tempDir)
	defer os.Setenv("ACKAGENT_CONFIG_DIR", origConfigDir)

	testKey, _ := hex.DecodeString("e6eb32e9739a52ef8e2c95aa9f1a7f2fddc8dd9fa79eef22c7a0d0f4e52f3d1a")

	cfg := createTestConfig([]config.KeyMetadata{
		{
			PublicKey: testKey,
			Purpose:   config.KeyPurposeAge,
		},
	})

	path, err := WriteIdentityFile(cfg)
	if err != nil {
		t.Fatalf("WriteIdentityFile() error = %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Errorf("WriteIdentityFile() did not create file at %v", path)
	}

	// Read file content
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read identity file: %v", err)
	}

	contentStr := string(content)

	// Should contain identity string
	if !strings.Contains(contentStr, IdentityPrefix) {
		t.Errorf("identity file should contain identity prefix")
	}

	// Should contain comment header
	if !strings.Contains(contentStr, "# ackagent age identity") {
		t.Errorf("identity file should contain comment header")
	}

	// Verify file permissions
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("failed to stat identity file: %v", err)
	}

	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("identity file permissions = %o, want 0600", perm)
	}
}

func TestWriteIdentityFileNoAgeKey(t *testing.T) {
	cfg := createTestConfig([]config.KeyMetadata{}) // No keys

	_, err := WriteIdentityFile(cfg)
	if err == nil {
		t.Error("WriteIdentityFile() should fail when no age key exists")
	}
}

func TestWriteIdentityFileCreatesDirectory(t *testing.T) {
	// Create a temp directory for testing
	tempDir := t.TempDir()
	nestedDir := filepath.Join(tempDir, "nested", "config", "dir")

	// Override config dir temporarily
	origConfigDir := os.Getenv("ACKAGENT_CONFIG_DIR")
	os.Setenv("ACKAGENT_CONFIG_DIR", nestedDir)
	defer os.Setenv("ACKAGENT_CONFIG_DIR", origConfigDir)

	testKey, _ := hex.DecodeString("e6eb32e9739a52ef8e2c95aa9f1a7f2fddc8dd9fa79eef22c7a0d0f4e52f3d1a")

	cfg := createTestConfig([]config.KeyMetadata{
		{
			PublicKey: testKey,
			Purpose:   config.KeyPurposeAge,
		},
	})

	path, err := WriteIdentityFile(cfg)
	if err != nil {
		t.Fatalf("WriteIdentityFile() error = %v", err)
	}

	// Verify nested directory was created
	if _, err := os.Stat(filepath.Dir(path)); os.IsNotExist(err) {
		t.Error("WriteIdentityFile() should create parent directories")
	}
}

func TestPluginConstants(t *testing.T) {
	// Verify constants are consistent with age plugin conventions
	if StanzaType != "ackagent" {
		t.Errorf("StanzaType = %v, want 'ackagent'", StanzaType)
	}

	if !strings.HasPrefix(RecipientPrefix, "age1") {
		t.Errorf("RecipientPrefix = %v, should start with 'age1'", RecipientPrefix)
	}

	if !strings.HasPrefix(IdentityPrefix, "AGE-PLUGIN-") {
		t.Errorf("IdentityPrefix = %v, should start with 'AGE-PLUGIN-'", IdentityPrefix)
	}
}

func TestWriteIdentityFileMultipleKeys(t *testing.T) {
	tempDir := t.TempDir()

	origConfigDir := os.Getenv("ACKAGENT_CONFIG_DIR")
	os.Setenv("ACKAGENT_CONFIG_DIR", tempDir)
	defer os.Setenv("ACKAGENT_CONFIG_DIR", origConfigDir)

	testKey1, _ := hex.DecodeString("e6eb32e9739a52ef8e2c95aa9f1a7f2fddc8dd9fa79eef22c7a0d0f4e52f3d1a")
	testKey2, _ := hex.DecodeString("a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890")

	cfg := createTestConfig([]config.KeyMetadata{
		{PublicKey: testKey1, Purpose: config.KeyPurposeAge},
		{PublicKey: testKey2, Purpose: config.KeyPurposeAge},
	})

	path, err := WriteIdentityFile(cfg)
	if err != nil {
		t.Fatalf("WriteIdentityFile() error = %v", err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read: %v", err)
	}
	contentStr := string(content)

	// Should contain multi-key header
	if !strings.Contains(contentStr, "2 keys") {
		t.Error("multi-key file should mention key count")
	}

	// Should contain two identity lines
	identityCount := strings.Count(contentStr, IdentityPrefix)
	if identityCount != 2 {
		t.Errorf("expected 2 identity lines, got %d", identityCount)
	}
}

func TestExportedConfigFunctions(t *testing.T) {
	// Test that the exported wrappers return reasonable values
	configPath := ConfigPath()
	if configPath == "" {
		t.Error("ConfigPath() should not be empty")
	}

	configDir := ConfigDir()
	if configDir == "" {
		t.Error("ConfigDir() should not be empty")
	}

	profilesDir := ProfilesDir()
	if profilesDir == "" {
		t.Error("ProfilesDir() should not be empty")
	}

	if !strings.Contains(configPath, configDir) {
		t.Errorf("ConfigPath() (%s) should contain ConfigDir() (%s)", configPath, configDir)
	}
}

func TestExportedKeyPurpose(t *testing.T) {
	if KeyPurposeAge != config.KeyPurposeAge {
		t.Errorf("KeyPurposeAge = %v, want %v", KeyPurposeAge, config.KeyPurposeAge)
	}
}

func TestPluginLazyConfigLoad(t *testing.T) {
	p := NewPlugin()

	// Config should be nil initially
	if p.cfg != nil {
		t.Error("Plugin.cfg should be nil initially")
	}

	// Note: We can't fully test getConfig() without a valid config file
	// Integration tests should cover this
}
