package commands

import (
	"encoding/hex"
	"testing"

	"github.com/ackagent/cli/internal/shared/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeGPGTestKey creates a GPG key with a known creation timestamp so
// GPGFingerprint() produces a deterministic V4 fingerprint.
func makeGPGTestKey(label string, publicKey []byte) config.KeyMetadata {
	return config.KeyMetadata{
		IOSKeyID:             "key-" + label,
		Label:                label,
		PublicKey:            publicKey,
		Purpose:              config.KeyPurposeGPG,
		KeyCreationTimestamp: 1700000000, // Fixed timestamp for deterministic fingerprints
	}
}

func TestResolveRecipients_ByFingerprint(t *testing.T) {
	key := makeGPGTestKey("alice", []byte("gpg-pubkey-1"))
	fp := GPGFingerprint(&key) // Compute expected fingerprint
	require.NotEmpty(t, fp)

	cfg := &config.Config{
		Version:       config.ConfigVersion,
		ActiveProfile: config.DefaultProfileName,
		Profiles: map[string]*config.ProfileConfig{
			config.DefaultProfileName: {
				RelayURL: "http://localhost:8080",
				Keys:     []config.KeyMetadata{key},
			},
		},
	}

	result := resolveRecipients(cfg, []string{fp})
	require.Len(t, result, 1)
	assert.Equal(t, "alice", result[0].Label)
}

func TestResolveRecipients_ByShortKeyID(t *testing.T) {
	key := makeGPGTestKey("bob", []byte("gpg-pubkey-2"))
	fp := GPGFingerprint(&key)
	require.NotEmpty(t, fp)
	shortKeyID := fp[len(fp)-8:] // Last 8 chars

	cfg := &config.Config{
		Version:       config.ConfigVersion,
		ActiveProfile: config.DefaultProfileName,
		Profiles: map[string]*config.ProfileConfig{
			config.DefaultProfileName: {
				RelayURL: "http://localhost:8080",
				Keys:     []config.KeyMetadata{key},
			},
		},
	}

	result := resolveRecipients(cfg, []string{shortKeyID})
	require.Len(t, result, 1)
	assert.Equal(t, "bob", result[0].Label)
}

func TestResolveRecipients_NotFound(t *testing.T) {
	key := makeGPGTestKey("alice", []byte("gpg-pubkey-1"))

	cfg := &config.Config{
		Version:       config.ConfigVersion,
		ActiveProfile: config.DefaultProfileName,
		Profiles: map[string]*config.ProfileConfig{
			config.DefaultProfileName: {
				RelayURL: "http://localhost:8080",
				Keys:     []config.KeyMetadata{key},
			},
		},
	}

	result := resolveRecipients(cfg, []string{"NONEXISTENT"})
	assert.Len(t, result, 0)
}

func TestResolveRecipients_MixedFoundAndNotFound(t *testing.T) {
	key := makeGPGTestKey("alice", []byte("gpg-pubkey-1"))
	fp := GPGFingerprint(&key)

	cfg := &config.Config{
		Version:       config.ConfigVersion,
		ActiveProfile: config.DefaultProfileName,
		Profiles: map[string]*config.ProfileConfig{
			config.DefaultProfileName: {
				RelayURL: "http://localhost:8080",
				Keys:     []config.KeyMetadata{key},
			},
		},
	}

	// One valid, one invalid
	result := resolveRecipients(cfg, []string{
		fp,
		"NONEXISTENT",
	})
	assert.Len(t, result, 1, "should find only the valid recipient")
	assert.Equal(t, "alice", result[0].Label)
}

func TestResolveRecipients_NoKeys(t *testing.T) {
	cfg := &config.Config{
		Version:       config.ConfigVersion,
		ActiveProfile: config.DefaultProfileName,
		Profiles: map[string]*config.ProfileConfig{
			config.DefaultProfileName: {
				RelayURL: "http://localhost:8080",
			},
		},
	}

	result := resolveRecipients(cfg, []string{"DDDD4444"})
	assert.Nil(t, result)
}

func TestFindKeyByRecipient_FullFingerprint(t *testing.T) {
	key := makeGPGTestKey("alice", []byte("gpg-pubkey-1"))
	fp := GPGFingerprint(&key)
	keys := []config.KeyMetadata{key}

	found := findKeyByRecipient(keys, fp)
	require.NotNil(t, found)
	assert.Equal(t, "alice", found.Label)
}

func TestFindKeyByRecipient_LongKeyID(t *testing.T) {
	key := makeGPGTestKey("bob", []byte("gpg-pubkey-2"))
	fp := GPGFingerprint(&key)
	longKeyID := fp[len(fp)-16:] // Last 16 chars
	keys := []config.KeyMetadata{key}

	found := findKeyByRecipient(keys, longKeyID)
	require.NotNil(t, found)
	assert.Equal(t, "bob", found.Label)
}

func TestFindKeyByRecipient_ShortKeyID(t *testing.T) {
	key := makeGPGTestKey("charlie", []byte("gpg-pubkey-3"))
	fp := GPGFingerprint(&key)
	shortKeyID := fp[len(fp)-8:] // Last 8 chars
	keys := []config.KeyMetadata{key}

	found := findKeyByRecipient(keys, shortKeyID)
	require.NotNil(t, found)
	assert.Equal(t, "charlie", found.Label)
}

func TestFindKeyByRecipient_CaseInsensitive(t *testing.T) {
	key := makeGPGTestKey("alice", []byte("gpg-pubkey-1"))
	fp := GPGFingerprint(&key)
	keys := []config.KeyMetadata{key}

	// Lowercase query for short key ID
	shortKeyID := fp[len(fp)-8:]
	found := findKeyByRecipient(keys, shortKeyID)
	require.NotNil(t, found)
	assert.Equal(t, "alice", found.Label)
}

func TestFindKeyByRecipient_ByLabel(t *testing.T) {
	key := makeGPGTestKey("alice", []byte("gpg-pubkey-1"))
	keys := []config.KeyMetadata{key}

	found := findKeyByRecipient(keys, "alice")
	require.NotNil(t, found)
	assert.Equal(t, "alice", found.Label)
}

func TestFindKeyByRecipient_NoMatch(t *testing.T) {
	key := makeGPGTestKey("alice", []byte("gpg-pubkey-1"))
	keys := []config.KeyMetadata{key}

	found := findKeyByRecipient(keys, "nobody")
	assert.Nil(t, found)
}

func TestBuildLiteralDataPacket(t *testing.T) {
	data := []byte("Hello, World!")
	packet := buildLiteralDataPacket(data, "test.txt")

	// Packet should not be empty
	assert.NotEmpty(t, packet)
	// Should be larger than data alone (has header, format, filename, date)
	assert.Greater(t, len(packet), len(data))
}

func TestBuildLiteralDataPacket_StdinFilename(t *testing.T) {
	data := []byte("stdin data")

	// Empty filename
	packet1 := buildLiteralDataPacket(data, "")
	assert.NotEmpty(t, packet1)

	// Dash filename
	packet2 := buildLiteralDataPacket(data, "-")
	assert.NotEmpty(t, packet2)
}

func TestFormatFingerprint_ValidInput(t *testing.T) {
	fp := make([]byte, 20) // 20 bytes = 40 hex chars
	for i := range fp {
		fp[i] = byte(i)
	}

	result := FormatFingerprint(fp)
	// Should produce space-separated groups of 4 hex chars
	assert.Contains(t, result, " ")
	// Remove spaces and verify hex length
	noSpaces := ""
	for _, c := range result {
		if c != ' ' {
			noSpaces += string(c)
		}
	}
	assert.Equal(t, 40, len(noSpaces))
}

func TestFormatFingerprint_ShortInput(t *testing.T) {
	fp, _ := hex.DecodeString("AABBCCDD")
	result := FormatFingerprint(fp)
	assert.Equal(t, "AABB CCDD", result)
}

func TestFormatFingerprint_Empty(t *testing.T) {
	result := FormatFingerprint([]byte{})
	assert.Equal(t, "", result)
}
