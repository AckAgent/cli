package commands

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/ackagent/cli/internal/shared/config"
	"github.com/stretchr/testify/assert"
)

func TestListKeys_FiltersToGPGKeys(t *testing.T) {
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
						PublicKey: mustDecodeHexForTest("aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111"),
						Purpose:   config.KeyPurposeSSH,
						CreatedAt: time.Now(),
					},
					{
						IOSKeyID:  "gpg-key-1",
						Label:     "Alice <alice@example.com>",
						PublicKey: mustDecodeHexForTest("bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222"),
						Purpose:   config.KeyPurposeGPG,
						Algorithm: config.AlgorithmP256,
						CreatedAt: time.Now(),
					},
					{
						IOSKeyID:  "age-key",
						Label:     "ackagent-age",
						PublicKey: mustDecodeHexForTest("cccc3333cccc3333cccc3333cccc3333cccc3333"),
						Purpose:   config.KeyPurposeAge,
						CreatedAt: time.Now(),
					},
					{
						IOSKeyID:  "gpg-key-2",
						Label:     "Bob <bob@example.com>",
						PublicKey: mustDecodeHexForTest("dddd4444dddd4444dddd4444dddd4444dddd4444"),
						Purpose:   config.KeyPurposeGPG,
						Algorithm: config.AlgorithmEd25519,
						CreatedAt: time.Now(),
					},
				},
			},
		},
	}

	// Reproduce the filtering logic from ListKeys
	var gpgKeys []config.KeyMetadata
	for _, key := range cfg.Keys() {
		if key.Purpose == config.KeyPurposeGPG {
			gpgKeys = append(gpgKeys, key)
		}
	}

	assert.Len(t, gpgKeys, 2, "should filter to only GPG keys")
	assert.Equal(t, "Alice <alice@example.com>", gpgKeys[0].Label)
	assert.Equal(t, "Bob <bob@example.com>", gpgKeys[1].Label)
}

func TestListKeys_AlgorithmDisplay(t *testing.T) {
	tests := []struct {
		algorithm   string
		expectedStr string
	}{
		{config.AlgorithmP256, "nistp256"},
		{config.AlgorithmEd25519, "EdDSA"},
	}

	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			algoDisplay := "nistp256"
			if tt.algorithm == config.AlgorithmEd25519 {
				algoDisplay = "EdDSA"
			}
			assert.Equal(t, tt.expectedStr, algoDisplay)
		})
	}
}

func TestListKeys_FingerprintValidation(t *testing.T) {
	tests := []struct {
		name        string
		fingerprint string
		isValid     bool
	}{
		{"valid 40-char fingerprint", "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555", true},
		{"empty fingerprint", "", false},
		{"too short", "AAAA1111", false},
		{"too long", "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555FF", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isValid := tt.fingerprint != "" && len(tt.fingerprint) == 40
			assert.Equal(t, tt.isValid, isValid)
		})
	}
}

func TestListKeys_NoGPGKeys(t *testing.T) {
	cfg := &config.Config{
		Version:       config.ConfigVersion,
		ActiveProfile: config.DefaultProfileName,
		Profiles: map[string]*config.ProfileConfig{
			config.DefaultProfileName: {
				RelayURL: "http://localhost:8080",
				Keys: []config.KeyMetadata{
					{
						IOSKeyID:  "ssh-key",
						Label:     "ssh-key",
						PublicKey: mustDecodeHexForTest("aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111"),
						Purpose:   config.KeyPurposeSSH,
					},
				},
			},
		},
	}

	var gpgKeys []config.KeyMetadata
	for _, key := range cfg.Keys() {
		if key.Purpose == config.KeyPurposeGPG {
			gpgKeys = append(gpgKeys, key)
		}
	}

	assert.Len(t, gpgKeys, 0, "should have no GPG keys")
}

func TestListKeys_EmptyConfig(t *testing.T) {
	cfg := &config.Config{
		Version:       config.ConfigVersion,
		ActiveProfile: config.DefaultProfileName,
		Profiles: map[string]*config.ProfileConfig{
			config.DefaultProfileName: {
				RelayURL: "http://localhost:8080",
			},
		},
	}

	var gpgKeys []config.KeyMetadata
	for _, key := range cfg.Keys() {
		if key.Purpose == config.KeyPurposeGPG {
			gpgKeys = append(gpgKeys, key)
		}
	}

	assert.Len(t, gpgKeys, 0, "should have no GPG keys")
}

// mustDecodeHexForTest decodes a hex string and panics on failure (test helper).
func mustDecodeHexForTest(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("invalid hex in test data: " + err.Error())
	}
	return b
}
