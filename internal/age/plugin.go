package age

import (
	"fmt"
	"os"
	"path/filepath"

	"filippo.io/age"
	"github.com/ackagent/cli/internal/shared/config"
)

// Plugin implements the age plugin interface.
// It provides recipients for encryption and identities for decryption.
type Plugin struct {
	// Config is loaded lazily when needed
	cfg *config.Config
}

// NewPlugin creates a new ackagent age plugin
func NewPlugin() *Plugin {
	return &Plugin{}
}

// Name returns the plugin name
func (p *Plugin) Name() string {
	return "ackagent"
}

// getConfig loads the config lazily
func (p *Plugin) getConfig() (*config.Config, error) {
	if p.cfg != nil {
		return p.cfg, nil
	}

	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	p.cfg = cfg
	return cfg, nil
}

// RecipientV1 returns a recipient for encryption.
// Called when age encounters a recipient string starting with "age1ackagent".
func (p *Plugin) RecipientV1(s string) (age.Recipient, error) {
	return ParseRecipient(s)
}

// IdentityV1 returns an identity for decryption.
// Called when age encounters an identity line starting with "AGE-PLUGIN-ACKAGENT-".
func (p *Plugin) IdentityV1(s string) (age.Identity, error) {
	identity, err := ParseIdentity(s)
	if err != nil {
		return nil, err
	}

	// Load config to find the key
	cfg, err := p.getConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	if !cfg.IsLoggedIn() {
		return nil, fmt.Errorf("not logged in: run 'ackagent login' first")
	}

	// Find the key by public key hex
	key, err := cfg.FindKey(identity.PublicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("age key not found (publicKeyHex=%s): %w", identity.PublicKeyHex, err)
	}

	if key.Purpose != config.KeyPurposeAge {
		return nil, fmt.Errorf("key is not an age key: %s", key.Purpose)
	}

	// Set up the identity with config and public key
	identity.Config = cfg
	identity.PublicKey = key.PublicKey

	// Get file info from stdin if available (for display purposes)
	fileName := "encrypted file"
	var fileSize int64 = 0

	// Create the unwrap function
	identity.UnwrapFunc = MakeUnwrapFunc(cfg, key, fileName, fileSize)

	return identity, nil
}

// GetRecipient returns the recipient string for the enrolled age key
func GetRecipient(cfg *config.Config) (string, error) {
	key := cfg.FindKeyByPurpose(config.KeyPurposeAge)
	if key == nil {
		return "", fmt.Errorf("no age key enrolled")
	}

	if key.AgeRecipient != "" {
		return key.AgeRecipient, nil
	}

	// Reconstruct recipient from public key
	recipient := &Recipient{PublicKey: key.PublicKey}
	return recipient.String(), nil
}

// GetIdentity returns the identity string for the enrolled age key
func GetIdentity(cfg *config.Config) (string, error) {
	key := cfg.FindKeyByPurpose(config.KeyPurposeAge)
	if key == nil {
		return "", fmt.Errorf("no age key enrolled")
	}

	identity := &Identity{PublicKeyHex: key.Hex()}
	return identity.String(), nil
}

// GetIdentityFilePath returns the recommended path for the identity file
func GetIdentityFilePath() string {
	return filepath.Join(config.ConfigDir(), "age-identity.txt")
}

// WriteIdentityFile writes all identities to the standard location
func WriteIdentityFile(cfg *config.Config) (string, error) {
	ageKeys := cfg.KeysForPurpose(config.KeyPurposeAge)
	if len(ageKeys) == 0 {
		return "", fmt.Errorf("no age key enrolled")
	}

	path := GetIdentityFilePath()

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return "", err
	}

	// Write identity file with all identities
	var content string
	if len(ageKeys) == 1 {
		content = "# ackagent age identity\n# Created by: ackagent age identity\n"
	} else {
		content = fmt.Sprintf("# ackagent age identities (%d keys)\n# Created by: ackagent age identity\n", len(ageKeys))
	}

	for _, key := range ageKeys {
		identity := &Identity{PublicKeyHex: key.Hex()}
		content += fmt.Sprintf("%s\n", identity.String())
	}

	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		return "", err
	}

	return path, nil
}
