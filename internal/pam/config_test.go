package pam

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig_Minimal(t *testing.T) {
	// Create config with minimal required fields
	configContent := `
[organization]
id = "acme-corp"
domain = "acme.com"
service_account_id = "sa-123"
api_key = "test-api-key"
`

	configFile, err := os.CreateTemp("", "pam-config-*.toml")
	require.NoError(t, err)
	defer os.Remove(configFile.Name())
	_, err = configFile.WriteString(configContent)
	require.NoError(t, err)
	configFile.Close()

	cfg, err := LoadConfigUnsafe(configFile.Name())
	require.NoError(t, err)

	assert.Equal(t, "acme-corp", cfg.Organization.ID)
	assert.Equal(t, "acme.com", cfg.Organization.Domain)
	assert.Equal(t, "sa-123", cfg.Organization.ServiceAccountID)
	assert.Equal(t, "test-api-key", cfg.Organization.APIKey)

	// Check defaults were applied
	assert.Equal(t, AuthModeFallback, cfg.Auth.Mode)
	assert.Equal(t, int64(120), cfg.Auth.Timeout)
	assert.Equal(t, int64(1000), cfg.Auth.PollIntervalMs)
	assert.False(t, cfg.Auth.RequireAttestation)

	assert.False(t, cfg.Cache.Enabled)
	assert.Equal(t, "5m", cfg.Cache.SyncInterval)
	assert.Equal(t, "/var/lib/ackagent/device-keys.cache", cfg.Cache.CacheFile)

	assert.Equal(t, "https://login.ackagent.com", cfg.API.LoginURL)
	assert.Equal(t, "https://relay.ackagent.com", cfg.API.RelayURL)
	assert.Equal(t, "https://oidc.ackagent.com", cfg.API.OIDCURL)
}

func TestLoadConfig_Full(t *testing.T) {
	configContent := `
[organization]
id = "acme-corp"
domain = "acme.com"
service_account_id = "sa-456"
api_key = "full-test-key"

[users]
admin = "cto@acme.com"
deploy = "ops-team@acme.com"

[auth]
mode = "push"
timeout = 60
require_attestation = true
poll_interval_ms = 500

[cache]
enabled = true
sync_users = ["admin", "deploy"]
sync_interval = "10m"
cache_file = "/tmp/ackagent.cache"

[api]
login_url = "https://login.example.com"
relay_url = "https://relay.example.com"
oidc_url = "https://oidc.example.com"
`

	configFile, err := os.CreateTemp("", "pam-config-*.toml")
	require.NoError(t, err)
	defer os.Remove(configFile.Name())
	_, err = configFile.WriteString(configContent)
	require.NoError(t, err)
	configFile.Close()

	cfg, err := LoadConfigUnsafe(configFile.Name())
	require.NoError(t, err)

	assert.Equal(t, "sa-456", cfg.Organization.ServiceAccountID)
	assert.Equal(t, "full-test-key", cfg.Organization.APIKey)

	assert.Equal(t, AuthModePush, cfg.Auth.Mode)
	assert.Equal(t, int64(60), cfg.Auth.Timeout)
	assert.True(t, cfg.Auth.RequireAttestation)
	assert.Equal(t, int64(500), cfg.Auth.PollIntervalMs)

	assert.True(t, cfg.Cache.Enabled)
	assert.Equal(t, []string{"admin", "deploy"}, cfg.Cache.SyncUsers)
	assert.Equal(t, "10m", cfg.Cache.SyncInterval)
	assert.Equal(t, "/tmp/ackagent.cache", cfg.Cache.CacheFile)

	assert.Equal(t, "https://login.example.com", cfg.API.LoginURL)
	assert.Equal(t, "https://relay.example.com", cfg.API.RelayURL)
	assert.Equal(t, "https://oidc.example.com", cfg.API.OIDCURL)
}

func TestGetUserEmail(t *testing.T) {
	cfg := &Config{
		Organization: OrganizationConfig{
			Domain: "acme.com",
		},
		Users: map[string]string{
			"admin":  "cto@acme.com",
			"deploy": "ops-team@acme.com",
		},
	}

	// Explicit mappings
	assert.Equal(t, "cto@acme.com", cfg.GetUserEmail("admin"))
	assert.Equal(t, "ops-team@acme.com", cfg.GetUserEmail("deploy"))

	// Default mapping
	assert.Equal(t, "john@acme.com", cfg.GetUserEmail("john"))
	assert.Equal(t, "testuser@acme.com", cfg.GetUserEmail("testuser"))
}

func TestLoadConfig_MissingOrgID(t *testing.T) {
	configContent := `
[organization]
domain = "acme.com"
service_account_id = "sa-123"
api_key = "test-key"
`

	configFile, err := os.CreateTemp("", "pam-config-*.toml")
	require.NoError(t, err)
	defer os.Remove(configFile.Name())
	configFile.WriteString(configContent)
	configFile.Close()

	_, err = LoadConfigUnsafe(configFile.Name())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "organization.id")
}

func TestLoadConfig_MissingServiceAccountID(t *testing.T) {
	configContent := `
[organization]
id = "acme-corp"
domain = "acme.com"
api_key = "test-key"
`

	configFile, err := os.CreateTemp("", "pam-config-*.toml")
	require.NoError(t, err)
	defer os.Remove(configFile.Name())
	configFile.WriteString(configContent)
	configFile.Close()

	_, err = LoadConfigUnsafe(configFile.Name())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "organization.service_account_id")
}

func TestLoadConfig_MissingAPIKey(t *testing.T) {
	configContent := `
[organization]
id = "acme-corp"
domain = "acme.com"
service_account_id = "sa-123"
`

	configFile, err := os.CreateTemp("", "pam-config-*.toml")
	require.NoError(t, err)
	defer os.Remove(configFile.Name())
	configFile.WriteString(configContent)
	configFile.Close()

	_, err = LoadConfigUnsafe(configFile.Name())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "organization.api_key")
}

func TestLoadConfig_InvalidAuthMode(t *testing.T) {
	configContent := `
[organization]
id = "acme-corp"
domain = "acme.com"
service_account_id = "sa-123"
api_key = "test-key"

[auth]
mode = "invalid"
`

	configFile, err := os.CreateTemp("", "pam-config-*.toml")
	require.NoError(t, err)
	defer os.Remove(configFile.Name())
	configFile.WriteString(configContent)
	configFile.Close()

	_, err = LoadConfigUnsafe(configFile.Name())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "auth.mode")
}

func TestLoadConfig_ConfigNotFound(t *testing.T) {
	_, err := LoadConfigUnsafe(filepath.Join(os.TempDir(), "nonexistent-config.toml"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrConfigNotFound)
}

// --- Path validation tests ---

func TestValidateConfigPath_RejectsPathTraversal(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"dotdot in middle", "/etc/ackagent/../tmp/evil.conf"},
		{"dotdot at start", "../etc/ackagent/pam.conf"},
		{"dotdot at end", "/etc/ackagent/subdir/.."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validateConfigPath(tt.path)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInsecurePath)
			assert.Contains(t, err.Error(), "..")
		})
	}
}

func TestValidateConfigPath_RejectsOutsideAllowedDir(t *testing.T) {
	// Create a real file outside AllowedConfigDir to avoid "not found" errors.
	tmpFile, err := os.CreateTemp("", "pam-outside-*.conf")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	_, err = validateConfigPath(tmpFile.Name())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInsecurePath)
	assert.Contains(t, err.Error(), "outside")
}

func TestValidateConfigPath_RejectsSymlinkOutsideAllowedDir(t *testing.T) {
	// Create a temp dir that looks like /etc/ackagent but has a symlink pointing out.
	tmpDir, err := os.MkdirTemp("", "pam-symlink-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	target, err := os.CreateTemp("", "pam-target-*.conf")
	require.NoError(t, err)
	defer os.Remove(target.Name())
	target.Close()

	// Create a symlink inside the fake dir.
	linkPath := filepath.Join(tmpDir, "evil.conf")
	err = os.Symlink(target.Name(), linkPath)
	require.NoError(t, err)

	// Even if someone passes this path, it should be rejected because
	// the resolved path is outside AllowedConfigDir.
	_, err = validateConfigPath(linkPath)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInsecurePath)
}

func TestValidateConfigPath_NonexistentFile(t *testing.T) {
	_, err := validateConfigPath("/etc/ackagent/nonexistent.conf")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrConfigNotFound)
}

// --- File permission validation tests ---

func TestValidateFilePermissions_WorldReadable(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "pam-perm-*.conf")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	// Set world-readable permissions
	err = os.Chmod(tmpFile.Name(), 0644)
	require.NoError(t, err)

	err = validateFilePermissions(tmpFile.Name())
	require.Error(t, err)
	// On macOS/Linux running as non-root, it will fail on ownership check.
	// If running as root, it would fail on permissions.
	assert.True(t, errors.Is(err, ErrInsecurePermission) || errors.Is(err, ErrInsecureOwnership),
		"expected ErrInsecurePermission or ErrInsecureOwnership, got: %v", err)
}

func TestValidateFilePermissions_WorldWritable(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "pam-perm-*.conf")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	// Set world-writable permissions
	err = os.Chmod(tmpFile.Name(), 0666)
	require.NoError(t, err)

	err = validateFilePermissions(tmpFile.Name())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInsecurePermission) || errors.Is(err, ErrInsecureOwnership),
		"expected ErrInsecurePermission or ErrInsecureOwnership, got: %v", err)
}

func TestValidateFilePermissions_GroupWritable(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "pam-perm-*.conf")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	// Set group-write permissions
	err = os.Chmod(tmpFile.Name(), 0660)
	require.NoError(t, err)

	err = validateFilePermissions(tmpFile.Name())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInsecurePermission) || errors.Is(err, ErrInsecureOwnership),
		"expected ErrInsecurePermission or ErrInsecureOwnership, got: %v", err)
}

func TestValidateFilePermissions_NonRootOwnership(t *testing.T) {
	// When running as non-root, temp files are owned by the current user.
	// This test verifies that non-root ownership is rejected.
	if os.Getuid() == 0 {
		t.Skip("test requires non-root user")
	}

	tmpFile, err := os.CreateTemp("", "pam-perm-*.conf")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	err = os.Chmod(tmpFile.Name(), 0600)
	require.NoError(t, err)

	err = validateFilePermissions(tmpFile.Name())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInsecureOwnership)
}

func TestValidateFilePermissions_RejectsSymlink(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "pam-target-*.conf")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	tmpDir, err := os.MkdirTemp("", "pam-symlink-perm-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	linkPath := filepath.Join(tmpDir, "link.conf")
	err = os.Symlink(tmpFile.Name(), linkPath)
	require.NoError(t, err)

	err = validateFilePermissions(linkPath)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInsecurePath)
}
