// Package pam provides PAM authentication via AckAgent push-based approval.
// When a user attempts to authenticate (SSH, sudo, login, etc.), a push notification
// is sent to their enrolled iOS device for approval.
package pam

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/BurntSushi/toml"
)

// DefaultConfigPath is the default path for PAM configuration.
const DefaultConfigPath = "/etc/ackagent/pam.conf"

// AllowedConfigDir is the required parent directory for PAM configuration files.
const AllowedConfigDir = "/etc/ackagent"

// Configuration errors.
var (
	ErrMissingField       = errors.New("missing required field")
	ErrInvalidValue       = errors.New("invalid value")
	ErrConfigNotFound     = errors.New("configuration file not found")
	ErrKeyFileNotFound    = errors.New("private key file not found") // Kept for key.go LoadSigningKey
	ErrInsecurePath       = errors.New("insecure config path")
	ErrInsecurePermission = errors.New("insecure file permissions")
	ErrInsecureOwnership  = errors.New("insecure file ownership")
)

// AuthMode defines the authentication mode.
type AuthMode string

const (
	// AuthModePush sends push notification only - fails if unreachable.
	AuthModePush AuthMode = "push"
	// AuthModeChallenge uses offline challenge-response only.
	AuthModeChallenge AuthMode = "challenge"
	// AuthModeFallback tries push first, falls back to challenge.
	AuthModeFallback AuthMode = "fallback"
)

// Config is the main configuration structure for the PAM module.
// Configuration is read from /etc/ackagent/pam.conf (TOML format).
type Config struct {
	Organization OrganizationConfig `toml:"organization"`
	Users        map[string]string  `toml:"users"`
	Auth         AuthConfig         `toml:"auth"`
	Cache        CacheConfig        `toml:"cache"`
	API          APIConfig          `toml:"api"`
}

// OrganizationConfig contains organization identification settings.
type OrganizationConfig struct {
	// ID is the organization ID/slug.
	ID string `toml:"id"`
	// Domain is the organization domain for default email mapping.
	Domain string `toml:"domain"`
	// ServiceAccountID is the service account ID used as OAuth2 client_id.
	ServiceAccountID string `toml:"service_account_id"`
	// APIKey is the service account API key used as OAuth2 client_secret.
	APIKey string `toml:"api_key"`
}

// AuthConfig contains authentication behavior settings.
type AuthConfig struct {
	// Mode is the authentication mode (push, challenge, fallback).
	Mode AuthMode `toml:"mode"`
	// Timeout is the request timeout in seconds.
	Timeout int64 `toml:"timeout"`
	// RequireAttestation requires device attestation for approval.
	RequireAttestation bool `toml:"require_attestation"`
	// PollIntervalMs is the poll interval in milliseconds when waiting for approval.
	PollIntervalMs int64 `toml:"poll_interval_ms"`
}

// CacheConfig contains device key cache settings.
type CacheConfig struct {
	// Enabled enables device key caching.
	Enabled bool `toml:"enabled"`
	// SyncUsers is the list of users to sync device keys for.
	SyncUsers []string `toml:"sync_users"`
	// SyncInterval is the sync interval (e.g., "5m", "1h").
	SyncInterval string `toml:"sync_interval"`
	// CacheFile is the cache file path.
	CacheFile string `toml:"cache_file"`
}

// APIConfig contains API endpoint settings.
type APIConfig struct {
	// LoginURL is the login service base URL.
	LoginURL string `toml:"login_url"`
	// RelayURL is the relay service base URL.
	RelayURL string `toml:"relay_url"`
	// OIDCURL is the OIDC service base URL for OAuth2 token exchange.
	OIDCURL string `toml:"oidc_url"`
	// KeyAuthURL is the key-auth service base URL for device key lookups.
	KeyAuthURL string `toml:"keyauth_url"`
}

// validateConfigPath validates that the config file path is safe to read.
// It rejects paths containing "..", resolves symlinks, and verifies the
// resolved path resides under AllowedConfigDir.
func validateConfigPath(path string) (string, error) {
	// Reject paths containing ".." components before cleaning,
	// since filepath.Clean would silently resolve them.
	for _, part := range strings.Split(path, string(filepath.Separator)) {
		if part == ".." {
			return "", fmt.Errorf("%w: path contains '..': %s", ErrInsecurePath, path)
		}
	}

	cleaned := filepath.Clean(path)

	// Resolve symlinks to get the real path.
	resolved, err := filepath.EvalSymlinks(cleaned)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("%w: %s", ErrConfigNotFound, path)
		}
		return "", fmt.Errorf("failed to resolve config path: %w", err)
	}

	// Verify the resolved path is under AllowedConfigDir.
	absAllowed, err := filepath.Abs(AllowedConfigDir)
	if err != nil {
		return "", fmt.Errorf("failed to resolve allowed config dir: %w", err)
	}
	if !strings.HasPrefix(resolved, absAllowed+string(filepath.Separator)) && resolved != absAllowed {
		return "", fmt.Errorf("%w: resolved path %s is outside %s", ErrInsecurePath, resolved, AllowedConfigDir)
	}

	return resolved, nil
}

// validateFilePermissions checks that the file at path has secure ownership
// and permissions. On Unix systems, it requires root ownership (uid 0) and
// mode no more permissive than 0640 (owner read/write, group read).
// On non-Unix systems this check is a no-op.
func validateFilePermissions(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}

	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("failed to stat config file: %w", err)
	}

	// Reject symlinks — we should be working with the resolved path.
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s is a symlink", ErrInsecurePath, path)
	}

	// Check ownership: must be owned by root (uid 0).
	stat, ok := info.Sys().(*syscall.Stat_t)
	if ok && stat.Uid != 0 {
		return fmt.Errorf("%w: %s is owned by uid %d, expected 0", ErrInsecureOwnership, path, stat.Uid)
	}

	// Check permissions: must be 0600 or 0640 (no world access).
	perm := info.Mode().Perm()
	if perm&0o007 != 0 {
		return fmt.Errorf("%w: %s has world-accessible permissions %04o", ErrInsecurePermission, path, perm)
	}
	if perm&0o070 > 0o040 {
		return fmt.Errorf("%w: %s has group-write/exec permissions %04o", ErrInsecurePermission, path, perm)
	}

	return nil
}

// LoadConfig loads configuration from the specified path.
// The path is validated for safety: it must reside under AllowedConfigDir,
// must not contain ".." path components, and must have secure ownership
// and permissions (root-owned, mode 0600 or 0640).
func LoadConfig(path string) (*Config, error) {
	resolved, err := validateConfigPath(path)
	if err != nil {
		return nil, err
	}

	if err := validateFilePermissions(resolved); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(resolved)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrConfigNotFound, path)
		}
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	cfg.setDefaults()

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// LoadConfigUnsafe loads configuration from any path without path or
// permission validation. This is intended only for testing and development.
func LoadConfigUnsafe(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrConfigNotFound, path)
		}
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	cfg.setDefaults()

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// LoadDefaultConfig loads configuration from the default path.
func LoadDefaultConfig() (*Config, error) {
	return LoadConfig(DefaultConfigPath)
}

// setDefaults sets default values for optional fields.
func (c *Config) setDefaults() {
	// Auth defaults
	if c.Auth.Mode == "" {
		c.Auth.Mode = AuthModeFallback
	}
	if c.Auth.Timeout == 0 {
		c.Auth.Timeout = 120
	}
	if c.Auth.PollIntervalMs == 0 {
		c.Auth.PollIntervalMs = 1000
	}

	// Cache defaults
	if c.Cache.SyncInterval == "" {
		c.Cache.SyncInterval = "5m"
	}
	if c.Cache.CacheFile == "" {
		c.Cache.CacheFile = "/var/lib/ackagent/device-keys.cache"
	}

	// API defaults
	if c.API.LoginURL == "" {
		c.API.LoginURL = "https://login.ackagent.com"
	}
	if c.API.RelayURL == "" {
		c.API.RelayURL = "https://relay.ackagent.com"
	}
	if c.API.OIDCURL == "" {
		c.API.OIDCURL = "https://oidc.ackagent.com"
	}
	if c.API.KeyAuthURL == "" {
		c.API.KeyAuthURL = "https://enterprise.ackagent.com"
	}

	// Initialize Users map if nil
	if c.Users == nil {
		c.Users = make(map[string]string)
	}
}

// validate validates the configuration.
func (c *Config) validate() error {
	if c.Organization.ID == "" {
		return fmt.Errorf("%w: organization.id", ErrMissingField)
	}
	if c.Organization.Domain == "" {
		return fmt.Errorf("%w: organization.domain", ErrMissingField)
	}
	if c.Organization.ServiceAccountID == "" {
		return fmt.Errorf("%w: organization.service_account_id", ErrMissingField)
	}
	if c.Organization.APIKey == "" {
		return fmt.Errorf("%w: organization.api_key", ErrMissingField)
	}

	// Validate auth mode
	switch c.Auth.Mode {
	case AuthModePush, AuthModeChallenge, AuthModeFallback:
		// Valid
	default:
		return fmt.Errorf("%w for auth.mode: %s (must be push, challenge, or fallback)", ErrInvalidValue, c.Auth.Mode)
	}

	return nil
}

// GetUserEmail returns the AckAgent email for a local username.
// If an explicit mapping exists in the [users] section, it's used.
// Otherwise, the email is derived as username@domain.
func (c *Config) GetUserEmail(username string) string {
	if email, ok := c.Users[username]; ok {
		return email
	}
	return fmt.Sprintf("%s@%s", username, c.Organization.Domain)
}
