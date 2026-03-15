package main

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ackagent/cli/internal/shared/config"
)

func TestKeysCommand_Registered(t *testing.T) {
	found := false
	for _, sub := range rootCmd.Commands() {
		if sub.Use == "keys" {
			found = true
			break
		}
	}
	assert.True(t, found, "keys command should be registered as a subcommand of root")
}

func TestKeysCommand_SyncFlagExists(t *testing.T) {
	f := keysCmd.Flags().Lookup("sync")
	require.NotNil(t, f, "--sync flag should be defined")
	assert.Equal(t, "false", f.DefValue, "--sync should default to false")
}

func TestKeysCommand_ShortDescription(t *testing.T) {
	assert.NotEmpty(t, keysCmd.Short, "keys command should have a short description")
}

func TestComputeGPGFingerprintForKey_EmptyPublicKey(t *testing.T) {
	key := config.KeyMetadata{PublicKey: nil}
	assert.Equal(t, "", computeGPGFingerprintForKey(key))
}

func TestComputeGPGFingerprintForKey_Ed25519(t *testing.T) {
	// 32-byte Ed25519 public key
	pubKey := make([]byte, 32)
	for i := range pubKey {
		pubKey[i] = byte(i + 1)
	}
	key := config.KeyMetadata{
		PublicKey: pubKey,
		Algorithm: "ed25519",
		CreatedAt: time.Unix(1700000000, 0),
	}
	fp := computeGPGFingerprintForKey(key)
	assert.Len(t, fp, 40, "GPG fingerprint should be 40 hex chars")
	assert.Equal(t, strings.ToUpper(fp), fp, "fingerprint should be uppercase")
}

func TestComputeGPGFingerprintForKey_Ed25519_CaseInsensitive(t *testing.T) {
	pubKey := make([]byte, 32)
	for i := range pubKey {
		pubKey[i] = byte(i + 10)
	}
	key := config.KeyMetadata{
		PublicKey: pubKey,
		Algorithm: "Ed25519",
		CreatedAt: time.Unix(1700000000, 0),
	}
	fp := computeGPGFingerprintForKey(key)
	assert.Len(t, fp, 40, "should match Ed25519 variant with capital E")
}

func TestComputeGPGFingerprintForKey_P256(t *testing.T) {
	// 65-byte P-256 uncompressed public key: 0x04 || X(32) || Y(32)
	pubKey := make([]byte, 65)
	pubKey[0] = 0x04
	for i := 1; i < 65; i++ {
		pubKey[i] = byte(i)
	}
	key := config.KeyMetadata{
		PublicKey: pubKey,
		Algorithm: "ecdsa-sha2-nistp256",
		CreatedAt: time.Unix(1700000000, 0),
	}
	fp := computeGPGFingerprintForKey(key)
	assert.Len(t, fp, 40, "GPG fingerprint should be 40 hex chars")
	assert.Equal(t, strings.ToUpper(fp), fp, "fingerprint should be uppercase")
}

func TestComputeGPGFingerprintForKey_P256_KeyCreationTimestamp(t *testing.T) {
	pubKey := make([]byte, 65)
	pubKey[0] = 0x04
	for i := 1; i < 65; i++ {
		pubKey[i] = byte(i)
	}
	key1 := config.KeyMetadata{
		PublicKey:            pubKey,
		Algorithm:            "ecdsa",
		CreatedAt:            time.Unix(1700000000, 0),
		KeyCreationTimestamp: 1700000500,
	}
	key2 := config.KeyMetadata{
		PublicKey:            pubKey,
		Algorithm:            "ecdsa",
		CreatedAt:            time.Unix(1700000000, 0),
		KeyCreationTimestamp: 0, // uses CreatedAt
	}
	fp1 := computeGPGFingerprintForKey(key1)
	fp2 := computeGPGFingerprintForKey(key2)
	assert.NotEqual(t, fp1, fp2, "different timestamps should produce different fingerprints")
}

func TestComputeGPGFingerprintForKey_UnknownAlgorithm(t *testing.T) {
	pubKey := make([]byte, 48) // not 65 bytes, not Ed25519
	key := config.KeyMetadata{
		PublicKey: pubKey,
		Algorithm: "rsa-2048",
	}
	assert.Equal(t, "", computeGPGFingerprintForKey(key))
}

func TestComputeGPGFingerprintForKey_P256WrongPrefix(t *testing.T) {
	// 65 bytes but not starting with 0x04
	pubKey := make([]byte, 65)
	pubKey[0] = 0x02 // compressed, not uncompressed
	key := config.KeyMetadata{
		PublicKey: pubKey,
		Algorithm: "ecdsa",
	}
	assert.Equal(t, "", computeGPGFingerprintForKey(key))
}

func TestComputeSSHFP_EmptyKey(t *testing.T) {
	key := &config.KeyMetadata{PublicKey: nil}
	fp := computeSSHFP(key)
	// Empty key falls back to Hex()
	assert.Equal(t, "", fp)
}

func TestComputeSSHFP_Ed25519(t *testing.T) {
	pubKey := make([]byte, 32)
	for i := range pubKey {
		pubKey[i] = byte(i + 1)
	}
	key := &config.KeyMetadata{
		PublicKey: pubKey,
		Algorithm: "ed25519",
	}
	fp := computeSSHFP(key)
	assert.True(t, strings.HasPrefix(fp, "SHA256:"), "Ed25519 SSH fingerprint should start with SHA256:")
}

func TestComputeSSHFP_P256(t *testing.T) {
	// 33-byte compressed P-256 public key
	pubKey := make([]byte, 33)
	pubKey[0] = 0x02
	for i := 1; i < 33; i++ {
		pubKey[i] = byte(i)
	}
	key := &config.KeyMetadata{
		PublicKey: pubKey,
		Algorithm: "ecdsa",
	}
	fp := computeSSHFP(key)
	assert.True(t, strings.HasPrefix(fp, "SHA256:"), "P-256 SSH fingerprint should start with SHA256:")
}
