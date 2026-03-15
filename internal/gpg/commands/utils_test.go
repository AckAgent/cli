package commands

import (
	"testing"

	"github.com/ackagent/cli/internal/shared/config"
)

func TestFindKey_NoKeys(t *testing.T) {
	cfg := &config.Config{
		Version:       config.ConfigVersion,
		ActiveProfile: config.DefaultProfileName,
		Profiles: map[string]*config.ProfileConfig{
			config.DefaultProfileName: {
				RelayURL: "http://localhost:8080",
				// No keys
			},
		},
	}

	key := FindKey(cfg, "", config.KeyPurposeGPG)
	if key != nil {
		t.Error("Expected nil for config with no keys")
	}

	key = FindKey(cfg, "ABCD1234", config.KeyPurposeGPG)
	if key != nil {
		t.Error("Expected nil for config with no keys even with key ID specified")
	}
}

func TestFindKey_DefaultKey(t *testing.T) {
	key1 := makeGPGTestKey("My Key", []byte("pubkey-default"))

	cfg := &config.Config{
		Version:       config.ConfigVersion,
		ActiveProfile: config.DefaultProfileName,
		Profiles: map[string]*config.ProfileConfig{
			config.DefaultProfileName: {
				RelayURL: "http://localhost:8080",
				Keys:     []config.KeyMetadata{key1},
			},
		},
	}

	// Empty keyID should return first key
	key := FindKey(cfg, "", config.KeyPurposeGPG)
	if key == nil {
		t.Fatal("Expected to find default key")
	}
	if key.Label != "My Key" {
		t.Errorf("Expected label 'My Key', got %q", key.Label)
	}
}

func TestFindKey_ByFullFingerprint(t *testing.T) {
	key1 := makeGPGTestKey("Key 1", []byte("pubkey1"))
	key2 := makeGPGTestKey("Key 2", []byte("pubkey2"))
	fp2 := GPGFingerprint(&key2)

	cfg := &config.Config{
		Version:       config.ConfigVersion,
		ActiveProfile: config.DefaultProfileName,
		Profiles: map[string]*config.ProfileConfig{
			config.DefaultProfileName: {
				RelayURL: "http://localhost:8080",
				Keys:     []config.KeyMetadata{key1, key2},
			},
		},
	}

	key := FindKey(cfg, fp2, config.KeyPurposeGPG)
	if key == nil {
		t.Fatal("Expected to find key by full fingerprint")
	}
	if key.Label != "Key 2" {
		t.Errorf("Expected 'Key 2', got %q", key.Label)
	}
}

func TestFindKey_ByLongKeyID(t *testing.T) {
	key1 := makeGPGTestKey("Key 1", []byte("pubkey1"))
	fp := GPGFingerprint(&key1)
	longKeyID := fp[len(fp)-16:] // Last 16 hex chars

	cfg := &config.Config{
		Version:       config.ConfigVersion,
		ActiveProfile: config.DefaultProfileName,
		Profiles: map[string]*config.ProfileConfig{
			config.DefaultProfileName: {
				RelayURL: "http://localhost:8080",
				Keys:     []config.KeyMetadata{key1},
			},
		},
	}

	// Match last 16 hex chars (long key ID)
	key := FindKey(cfg, longKeyID, config.KeyPurposeGPG)
	if key == nil {
		t.Fatal("Expected to find key by long key ID (last 16 chars)")
	}
	if key.Label != "Key 1" {
		t.Errorf("Expected 'Key 1', got %q", key.Label)
	}
}

func TestFindKey_ByShortKeyID(t *testing.T) {
	key1 := makeGPGTestKey("Key 1", []byte("pubkey-short"))
	fp := GPGFingerprint(&key1)
	shortKeyID := fp[len(fp)-8:] // Last 8 hex chars

	cfg := &config.Config{
		Version:       config.ConfigVersion,
		ActiveProfile: config.DefaultProfileName,
		Profiles: map[string]*config.ProfileConfig{
			config.DefaultProfileName: {
				RelayURL: "http://localhost:8080",
				Keys:     []config.KeyMetadata{key1},
			},
		},
	}

	// Match last 8 hex chars (short key ID)
	key := FindKey(cfg, shortKeyID, config.KeyPurposeGPG)
	if key == nil {
		t.Fatal("Expected to find key by short key ID (last 8 chars)")
	}
	if key.Label != "Key 1" {
		t.Errorf("Expected 'Key 1', got %q", key.Label)
	}
}

func TestFindKey_ByLabel(t *testing.T) {
	key1 := makeGPGTestKey("WorkKey", []byte("pubkey1"))
	key2 := makeGPGTestKey("PersonalKey", []byte("pubkey2"))

	cfg := &config.Config{
		Version:       config.ConfigVersion,
		ActiveProfile: config.DefaultProfileName,
		Profiles: map[string]*config.ProfileConfig{
			config.DefaultProfileName: {
				RelayURL: "http://localhost:8080",
				Keys:     []config.KeyMetadata{key1, key2},
			},
		},
	}

	key := FindKey(cfg, "PersonalKey", config.KeyPurposeGPG)
	if key == nil {
		t.Fatal("Expected to find key by label")
	}
	if key.Label != "PersonalKey" {
		t.Errorf("Expected 'PersonalKey', got %q", key.Label)
	}
}

func TestFindKey_LabelCaseInsensitive(t *testing.T) {
	key1 := makeGPGTestKey("MyGPGKey", []byte("pubkey1"))

	cfg := &config.Config{
		Version:       config.ConfigVersion,
		ActiveProfile: config.DefaultProfileName,
		Profiles: map[string]*config.ProfileConfig{
			config.DefaultProfileName: {
				RelayURL: "http://localhost:8080",
				Keys:     []config.KeyMetadata{key1},
			},
		},
	}

	// Case insensitive label match
	key := FindKey(cfg, "mygpgkey", config.KeyPurposeGPG)
	if key == nil {
		t.Fatal("Expected case-insensitive label match")
	}
	if key.Label != "MyGPGKey" {
		t.Errorf("Expected 'MyGPGKey', got %q", key.Label)
	}
}

func TestFindKey_FingerprintCaseInsensitive(t *testing.T) {
	key1 := makeGPGTestKey("Key 1", []byte("pubkey-ci"))
	fp := GPGFingerprint(&key1)
	shortKeyID := fp[len(fp)-8:]

	cfg := &config.Config{
		Version:       config.ConfigVersion,
		ActiveProfile: config.DefaultProfileName,
		Profiles: map[string]*config.ProfileConfig{
			config.DefaultProfileName: {
				RelayURL: "http://localhost:8080",
				Keys:     []config.KeyMetadata{key1},
			},
		},
	}

	// Lowercase short key ID should match (GPG fingerprints are uppercased)
	key := FindKey(cfg, shortKeyID, config.KeyPurposeGPG)
	if key == nil {
		t.Fatal("Expected case-insensitive fingerprint match")
	}
}

func TestFindKey_NoMatch(t *testing.T) {
	key1 := makeGPGTestKey("Key 1", []byte("pubkey1"))

	cfg := &config.Config{
		Version:       config.ConfigVersion,
		ActiveProfile: config.DefaultProfileName,
		Profiles: map[string]*config.ProfileConfig{
			config.DefaultProfileName: {
				RelayURL: "http://localhost:8080",
				Keys:     []config.KeyMetadata{key1},
			},
		},
	}

	key := FindKey(cfg, "NONEXISTENT", config.KeyPurposeGPG)
	if key != nil {
		t.Error("Expected nil for non-matching key ID")
	}
}

func TestFindKey_MultipleKeys(t *testing.T) {
	key1 := makeGPGTestKey("Key 1", []byte("pubkey1"))
	key2 := makeGPGTestKey("Key 2", []byte("pubkey2"))
	key3 := makeGPGTestKey("Key 3", []byte("pubkey3"))
	fp2Short := GPGFingerprint(&key2)[len(GPGFingerprint(&key2))-8:]

	cfg := &config.Config{
		Version:       config.ConfigVersion,
		ActiveProfile: config.DefaultProfileName,
		Profiles: map[string]*config.ProfileConfig{
			config.DefaultProfileName: {
				RelayURL: "http://localhost:8080",
				Keys:     []config.KeyMetadata{key1, key2, key3},
			},
		},
	}

	// Should find specific key among multiple
	key := FindKey(cfg, fp2Short, config.KeyPurposeGPG)
	if key == nil {
		t.Fatal("Expected to find specific key")
	}
	if key.Label != "Key 2" {
		t.Errorf("Expected 'Key 2', got %q", key.Label)
	}
}

func TestFindKey_PurposeFilter_SkipsSSHKeys(t *testing.T) {
	gpgKey := makeGPGTestKey("Tim <tim@example.com>", []byte("gpg-pubkey"))

	cfg := &config.Config{
		Version:       config.ConfigVersion,
		ActiveProfile: config.DefaultProfileName,
		Profiles: map[string]*config.ProfileConfig{
			config.DefaultProfileName: {
				RelayURL: "http://localhost:8080",
				Keys: []config.KeyMetadata{
					{
						IOSKeyID:  "ssh-key",
						Label:     "ackagent-prod",
						PublicKey: []byte("ssh-pubkey"),
						Purpose:   config.KeyPurposeSSH,
					},
					gpgKey,
				},
			},
		},
	}

	// With empty keyID, should return the GPG key, not the SSH key
	key := FindKey(cfg, "", config.KeyPurposeGPG)
	if key == nil {
		t.Fatal("Expected to find GPG key")
	}
	if key.Label != "Tim <tim@example.com>" {
		t.Errorf("Expected GPG key label 'Tim <tim@example.com>', got %q", key.Label)
	}

	// SSH key should be findable with SSH purpose
	key = FindKey(cfg, "", config.KeyPurposeSSH)
	if key == nil {
		t.Fatal("Expected to find SSH key with SSH purpose")
	}
	if key.Label != "ackagent-prod" {
		t.Errorf("Expected SSH key label 'ackagent-prod', got %q", key.Label)
	}
}

func TestFindKey_PurposeFilter_NoMatchingPurpose(t *testing.T) {
	cfg := &config.Config{
		Version:       config.ConfigVersion,
		ActiveProfile: config.DefaultProfileName,
		Profiles: map[string]*config.ProfileConfig{
			config.DefaultProfileName: {
				RelayURL: "http://localhost:8080",
				Keys: []config.KeyMetadata{
					{
						IOSKeyID:  "ssh-key",
						Label:     "ackagent-prod",
						PublicKey: []byte("ssh-pubkey"),
						Purpose:   config.KeyPurposeSSH,
					},
					{
						IOSKeyID:  "age-key",
						Label:     "ackagent-age",
						PublicKey: []byte("age-pubkey"),
						Purpose:   config.KeyPurposeAge,
					},
				},
			},
		},
	}

	// No GPG keys enrolled, should return nil even with empty keyID
	key := FindKey(cfg, "", config.KeyPurposeGPG)
	if key != nil {
		t.Error("Expected nil when no GPG keys are enrolled")
	}
}

// Regression tests for the bug where GPG commands selected SSH keys.

// newMixedKeyConfig creates a config with SSH key enrolled before GPG key,
// reproducing the exact scenario from the original bug report.
func newMixedKeyConfig() *config.Config {
	gpgKey := makeGPGTestKey("Tim <tim@gmail.com>", []byte("gpg-pubkey"))

	return &config.Config{
		Version:       config.ConfigVersion,
		ActiveProfile: config.DefaultProfileName,
		Profiles: map[string]*config.ProfileConfig{
			config.DefaultProfileName: {
				RelayURL: "http://localhost:8080",
				Keys: []config.KeyMetadata{
					{
						IOSKeyID:  "ssh-key-1",
						Label:     "ackagent-prod",
						PublicKey: []byte("ssh-pubkey"),
						Purpose:   config.KeyPurposeSSH,
					},
					{
						IOSKeyID:  "age-key-1",
						Label:     "ackagent-age",
						PublicKey: []byte("age-pubkey"),
						Purpose:   config.KeyPurposeAge,
					},
					gpgKey,
				},
			},
		},
	}
}

func TestRegression_FindKeyDefaultSelectsGPGNotSSH(t *testing.T) {
	cfg := newMixedKeyConfig()

	key := FindKey(cfg, "", config.KeyPurposeGPG)
	if key == nil {
		t.Fatal("Expected to find a GPG key")
	}
	if key.Label == "ackagent-prod" {
		t.Fatal("REGRESSION: FindKey returned SSH key 'ackagent-prod' instead of GPG key")
	}
	if key.Label != "Tim <tim@gmail.com>" {
		t.Errorf("Expected GPG key 'Tim <tim@gmail.com>', got %q", key.Label)
	}
}

func TestRegression_FindKeyByLabelIgnoresWrongPurpose(t *testing.T) {
	cfg := newMixedKeyConfig()

	// Searching by SSH key label with GPG purpose should not find the SSH key
	key := FindKey(cfg, "ackagent-prod", config.KeyPurposeGPG)
	if key != nil {
		t.Fatal("REGRESSION: FindKey matched SSH key label when searching with GPG purpose")
	}

	// Searching by Age key label with GPG purpose should not find the Age key
	key = FindKey(cfg, "ackagent-age", config.KeyPurposeGPG)
	if key != nil {
		t.Fatal("REGRESSION: FindKey matched Age key label when searching with GPG purpose")
	}
}

func TestRegression_FindKeyByFingerprintIgnoresWrongPurpose(t *testing.T) {
	cfg := newMixedKeyConfig()

	// SSH key does not have a GPG fingerprint, so no matching is possible
	// Non-existent fingerprint should not match anything
	key := FindKey(cfg, "NONEXISTENT0000NONEXISTENT0000NONEXISTENT", config.KeyPurposeGPG)
	if key != nil {
		t.Fatal("REGRESSION: FindKey matched non-existent fingerprint when searching with GPG purpose")
	}
}

func TestRegression_ResolveRecipientsIgnoresSSHKeys(t *testing.T) {
	cfg := newMixedKeyConfig()

	// Find the GPG key fingerprint from the config
	gpgKeys := cfg.KeysForPurpose(config.KeyPurposeGPG)
	if len(gpgKeys) == 0 {
		t.Fatal("Expected at least one GPG key in mixed config")
	}
	gpgFingerprint := GPGFingerprint(&gpgKeys[0])

	result := resolveRecipients(cfg, []string{gpgFingerprint})
	if len(result) != 1 {
		t.Fatalf("Expected 1 recipient, got %d", len(result))
	}
	if result[0].Label != "Tim <tim@gmail.com>" {
		t.Errorf("Expected GPG key, got %q", result[0].Label)
	}

	// SSH key label should not resolve as a GPG recipient
	result = resolveRecipients(cfg, []string{"ackagent-prod"})
	if len(result) != 0 {
		t.Fatal("REGRESSION: resolveRecipients matched SSH key as GPG recipient")
	}
}

func TestRegression_FindKeyByRecipientOnFilteredSlice(t *testing.T) {
	key1 := makeGPGTestKey("alice", []byte("gpg-pubkey-1"))
	key2 := makeGPGTestKey("bob", []byte("gpg-pubkey-2"))
	fp1 := GPGFingerprint(&key1)
	fp2 := GPGFingerprint(&key2)
	fp1Short := fp1[len(fp1)-8:]

	gpgKeys := []config.KeyMetadata{key1, key2}

	// Match by label
	key := findKeyByRecipient(gpgKeys, "alice")
	if key == nil {
		t.Fatal("Expected to find Alice's key")
	}
	if key.Label != "alice" {
		t.Errorf("Expected Alice's key, got %q", key.Label)
	}

	// Match by full fingerprint
	key = findKeyByRecipient(gpgKeys, fp2)
	if key == nil {
		t.Fatal("Expected to find Bob's key by fingerprint")
	}
	if key.Label != "bob" {
		t.Errorf("Expected Bob's key, got %q", key.Label)
	}

	// Match by short key ID
	key = findKeyByRecipient(gpgKeys, fp1Short)
	if key == nil {
		t.Fatal("Expected to find Alice's key by short key ID")
	}
	if key.Label != "alice" {
		t.Errorf("Expected Alice's key, got %q", key.Label)
	}

	// Non-existent should return nil
	key = findKeyByRecipient(gpgKeys, "nobody")
	if key != nil {
		t.Error("Expected nil for non-existent recipient")
	}
}

func TestRegression_AllPurposesIndependent(t *testing.T) {
	cfg := newMixedKeyConfig()

	// Each purpose should only see its own keys
	tests := []struct {
		purpose       config.KeyPurpose
		expectedLabel string
	}{
		{config.KeyPurposeSSH, "ackagent-prod"},
		{config.KeyPurposeGPG, "Tim <tim@gmail.com>"},
		{config.KeyPurposeAge, "ackagent-age"},
	}

	for _, tc := range tests {
		t.Run(string(tc.purpose), func(t *testing.T) {
			key := FindKey(cfg, "", tc.purpose)
			if key == nil {
				t.Fatalf("Expected to find key for purpose %s", tc.purpose)
			}
			if key.Label != tc.expectedLabel {
				t.Errorf("Purpose %s: expected %q, got %q", tc.purpose, tc.expectedLabel, key.Label)
			}
		})
	}
}
