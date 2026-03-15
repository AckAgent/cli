package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ConfigPath returns the path to the config file
func ConfigPath() string {
	return filepath.Join(ConfigDir(), "config.json")
}

// ConfigDir returns the directory for config files
func ConfigDir() string {
	// Allow programmatic override for testing
	if configDirOverride != "" {
		cfgLog.Debug("using config dir override: %s", configDirOverride)
		return configDirOverride
	}

	// Check for environment variable (used by sk_provider and testing)
	if envDir := os.Getenv("ACKAGENT_CONFIG_DIR"); envDir != "" {
		cfgLog.Debug("using config dir from env ACKAGENT_CONFIG_DIR: %s", envDir)
		return envDir
	}
	cfgLog.Debug("ACKAGENT_CONFIG_DIR not set, using platform default")

	switch runtime.GOOS {
	case "darwin":
		home, _ := os.UserHomeDir()
		return filepath.Join(home, "Library", "Application Support", AppID)
	case "windows":
		appData := os.Getenv("APPDATA")
		if appData == "" {
			home, _ := os.UserHomeDir()
			appData = filepath.Join(home, "AppData", "Roaming")
		}
		return filepath.Join(appData, AppID)
	default: // linux and others
		if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
			return filepath.Join(xdg, AppID)
		}
		home, _ := os.UserHomeDir()
		return filepath.Join(home, ".config", AppID)
	}
}

// ProfilesDir returns the directory for profile files
func ProfilesDir() string {
	return filepath.Join(ConfigDir(), "profiles")
}

// ProfilePath returns the path to a profile file
func ProfilePath(name string) string {
	return filepath.Join(ProfilesDir(), name+".json")
}

// Load loads the configuration from disk
func Load() (*Config, error) {
	path := ConfigPath()
	cfgLog.Debug("loading config from %s", path)

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			cfgLog.Debug("config not found, using defaults")
			return NewDefault(), nil
		}
		cfgLog.Error("failed to read config: %v", err)
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	// First, parse into a temporary struct that can hold v2-style inline profiles
	var rawCfg struct {
		Version       int    `json:"version"`
		DeviceID      string `json:"device_id"`
		DeviceName    string `json:"device_name"`
		ActiveProfile string `json:"active_profile"`
	}
	if err := json.Unmarshal(data, &rawCfg); err != nil {
		cfgLog.Error("failed to parse config: %v", err)
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	cfg := &Config{
		Version:       rawCfg.Version,
		DeviceID:      rawCfg.DeviceID,
		DeviceName:    rawCfg.DeviceName,
		ActiveProfile: rawCfg.ActiveProfile,
		Profiles:      make(map[string]*ProfileConfig),
	}

	// Load profiles from files
	if err := cfg.loadAllProfiles(); err != nil {
		return nil, err
	}

	cfgLog.Debug("config loaded profile=%s profiles=%d", cfg.ActiveProfile, len(cfg.Profiles))
	return cfg, nil
}

// loadAllProfiles loads all profile files from the profiles directory
func (c *Config) loadAllProfiles() error {
	dir := ProfilesDir()

	// If profiles dir doesn't exist, that's ok for new installs
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("failed to read profiles directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".json")
		profile, err := loadProfileFile(name)
		if err != nil {
			cfgLog.Warn("failed to load profile %s: %v", name, err)
			continue
		}
		c.Profiles[name] = profile
	}
	return nil
}

// loadProfileFile loads a single profile from its file
func loadProfileFile(name string) (*ProfileConfig, error) {
	path := ProfilePath(name)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var profile ProfileConfig
	if err := json.Unmarshal(data, &profile); err != nil {
		return nil, err
	}
	return &profile, nil
}

// saveProfileFile saves a single profile to its file
func saveProfileFile(name string, profile *ProfileConfig) error {
	if err := os.MkdirAll(ProfilesDir(), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return err
	}
	path := ProfilePath(name)
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

// deleteProfileFile removes a profile file
func deleteProfileFile(name string) error {
	return os.Remove(ProfilePath(name))
}

// backupConfig creates a timestamped backup of the config file before saving.
// Backups are named config.json.backup.YYYY-MM-DDTHH-MM-SS
func backupConfig() error {
	path := ConfigPath()

	// Skip if config doesn't exist yet
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}

	// Create timestamped backup
	timestamp := time.Now().Format("2006-01-02T15-04-05")
	backupPath := path + ".backup." + timestamp

	// Copy current config to backup
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read config for backup: %w", err)
	}
	if err := os.WriteFile(backupPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write backup: %w", err)
	}

	cfgLog.Debug("created config backup: %s", backupPath)

	// Clean up old backups
	cleanupOldBackups()
	return nil
}

// cleanupOldBackups removes old backup files, keeping only the most recent maxBackups.
func cleanupOldBackups() {
	dir := ConfigDir()
	pattern := filepath.Join(dir, "config.json.backup.*")
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) <= maxBackups {
		return
	}

	// Sort by name (timestamps sort chronologically)
	sort.Strings(matches)

	// Delete oldest backups
	for _, path := range matches[:len(matches)-maxBackups] {
		if err := os.Remove(path); err != nil {
			cfgLog.Debug("failed to remove old backup %s: %v", path, err)
		} else {
			cfgLog.Debug("removed old backup: %s", path)
		}
	}
}

// Save saves the configuration and all profiles to disk
func (c *Config) Save() error {
	// Backup existing config before overwriting
	if err := backupConfig(); err != nil {
		cfgLog.Warn("failed to backup config: %v", err)
		// Continue with save even if backup fails
	}

	// Save config.json (global settings only)
	if err := c.saveConfigOnly(); err != nil {
		return err
	}

	// Save all profiles to their individual files
	for name, profile := range c.Profiles {
		if err := saveProfileFile(name, profile); err != nil {
			cfgLog.Error("failed to save profile %s: %v", name, err)
			return fmt.Errorf("failed to save profile %s: %w", name, err)
		}
	}

	cfgLog.Debug("config saved with %d profiles", len(c.Profiles))
	return nil
}

// saveConfigOnly saves just the config.json file (global settings, no profiles)
func (c *Config) saveConfigOnly() error {
	dir := ConfigDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		cfgLog.Error("failed to create config directory: %v", err)
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Since Profiles has json:"-", MarshalIndent will exclude it
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		cfgLog.Error("failed to marshal config: %v", err)
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Write atomically using temp file
	tmpPath := ConfigPath() + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		cfgLog.Error("failed to write config: %v", err)
		return fmt.Errorf("failed to write config: %w", err)
	}

	if err := os.Rename(tmpPath, ConfigPath()); err != nil {
		os.Remove(tmpPath)
		cfgLog.Error("failed to save config: %v", err)
		return fmt.Errorf("failed to save config: %w", err)
	}

	return nil
}

// SaveProfile saves a single profile to its file
func (c *Config) SaveProfile(name string) error {
	profile, ok := c.Profiles[name]
	if !ok {
		return fmt.Errorf("%w: %s", ErrProfileNotFound, name)
	}
	return saveProfileFile(name, profile)
}

// NewDefault creates a new default configuration and saves it to disk
func NewDefault() *Config {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "Desktop"
	}

	defaultProfile := &ProfileConfig{
		RelayURL: "http://localhost:8080",
		Keys:     []KeyMetadata{},
	}

	cfg := &Config{
		Version:       ConfigVersion,
		DeviceID:      uuid.New().String(),
		DeviceName:    hostname,
		ActiveProfile: DefaultProfileName,
		Profiles: map[string]*ProfileConfig{
			DefaultProfileName: defaultProfile,
		},
	}

	// Save both config.json and the default profile
	if err := cfg.Save(); err != nil {
		cfgLog.Error("failed to save default config: %v", err)
	}

	return cfg
}
