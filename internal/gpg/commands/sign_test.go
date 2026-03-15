package commands

import (
	"testing"
	"time"

	"github.com/ackagent/cli/internal/gpg/cli"
	"github.com/ackagent/cli/internal/shared/config"
	"github.com/stretchr/testify/assert"
)

// TestSign_RequiresLogin verifies that Sign checks for login before proceeding.
// Since Sign calls os.Exit(1), we verify the prerequisite checks instead.

func TestSign_NoKeyID_SingleGPGKey(t *testing.T) {
	key1 := makeGPGTestKey("Test GPG Key <test@example.com>", []byte("pubkey1"))
	key1.IOSKeyID = "key-1"
	key1.CreatedAt = time.Now()

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

	args := &cli.Args{
		Mode:      cli.ModeDetach,
		LocalUser: "",
	}

	key := FindKey(cfg, args.LocalUser, config.KeyPurposeGPG)
	assert.NotNil(t, key, "should find the single GPG key when no local-user specified")
	assert.Equal(t, "Test GPG Key <test@example.com>", key.Label)
}

func TestSign_NoKeyID_MultipleGPGKeys(t *testing.T) {
	key1 := makeGPGTestKey("Work Key <work@example.com>", []byte("pubkey1"))
	key1.IOSKeyID = "key-1"
	key1.CreatedAt = time.Now()

	key2 := makeGPGTestKey("Personal Key <me@example.com>", []byte("pubkey2"))
	key2.IOSKeyID = "key-2"
	key2.CreatedAt = time.Now()

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

	keys := cfg.KeysForPurpose(config.KeyPurposeGPG)
	assert.Len(t, keys, 2, "should have two GPG keys")
}

func TestSign_NotLoggedIn(t *testing.T) {
	cfg := &config.Config{
		Version:       config.ConfigVersion,
		ActiveProfile: config.DefaultProfileName,
		Profiles: map[string]*config.ProfileConfig{
			config.DefaultProfileName: {
				RelayURL: "http://localhost:8080",
			},
		},
	}

	assert.False(t, cfg.IsLoggedIn(), "config should not be logged in")
}

func TestSign_KeyFingerprint_ECDSAvsEd25519(t *testing.T) {
	ecdsaKey := config.KeyMetadata{
		Algorithm: config.AlgorithmP256,
	}
	ed25519Key := config.KeyMetadata{
		Algorithm: config.AlgorithmEd25519,
	}

	assert.False(t, ecdsaKey.IsEd25519(), "P-256 key should not be Ed25519")
	assert.True(t, ed25519Key.IsEd25519(), "Ed25519 key should be identified as Ed25519")
}
