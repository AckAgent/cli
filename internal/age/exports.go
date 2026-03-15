package age

import (
	"github.com/ackagent/cli/internal/shared/config"
)

// Re-export config types for plugin binary
type Config = config.Config
type KeyMetadata = config.KeyMetadata

const KeyPurposeAge = config.KeyPurposeAge

// LoadConfig loads the CLI configuration
func LoadConfig() (*config.Config, error) {
	return config.Load()
}

// ConfigPath returns the path to the config file
func ConfigPath() string {
	return config.ConfigPath()
}

// ConfigDir returns the config directory
func ConfigDir() string {
	return config.ConfigDir()
}

// ProfilesDir returns the profiles directory
func ProfilesDir() string {
	return config.ProfilesDir()
}
