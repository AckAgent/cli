package pam

import (
	"os"
	"path/filepath"
	"testing"

	keyauthapi "github.com/ackagent/api/go/keyauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeviceKeyCache_LoadSave(t *testing.T) {
	// Create temp file
	tmpDir := t.TempDir()
	cachePath := filepath.Join(tmpDir, "cache.json")

	// Create and save cache
	cache, err := LoadDeviceKeyCache(cachePath)
	require.NoError(t, err)

	cache.SetOrgID("test-org")
	deviceName := "iPhone"
	cache.SetUserDevices("user@example.com", []keyauthapi.DeviceKeyInfo{
		{
			ApproverId:             "approver-uuid-1",
			EncryptionPublicKeyHex: "aabbccdd",
			AuthPublicKeyHex:       "eeff0011",
			DeviceName:             &deviceName,
		},
	})

	err = cache.Save()
	require.NoError(t, err)

	// Load and verify
	loaded, err := LoadDeviceKeyCache(cachePath)
	require.NoError(t, err)

	devices := loaded.GetUserDevices("user@example.com")
	require.Len(t, devices, 1)
	assert.Equal(t, "approver-uuid-1", devices[0].ApproverId)
	assert.Equal(t, "aabbccdd", devices[0].EncryptionPublicKeyHex)
	assert.Equal(t, "iPhone", *devices[0].DeviceName)
}

func TestDeviceKeyCache_GetDevice(t *testing.T) {
	cache := &DeviceKeyCache{
		users: make(map[string]*CachedUser),
	}

	cache.SetUserDevices("user@example.com", []keyauthapi.DeviceKeyInfo{
		{ApproverId: "approver-uuid-1", EncryptionPublicKeyHex: "key1", AuthPublicKeyHex: "auth1"},
		{ApproverId: "approver-uuid-2", EncryptionPublicKeyHex: "key2", AuthPublicKeyHex: "auth2"},
	})

	// Get existing device
	device := cache.GetDevice("user@example.com", "approver-uuid-1")
	require.NotNil(t, device)
	assert.Equal(t, "key1", device.EncryptionPublicKeyHex)

	// Get another device
	device = cache.GetDevice("user@example.com", "approver-uuid-2")
	require.NotNil(t, device)
	assert.Equal(t, "key2", device.EncryptionPublicKeyHex)

	// Non-existent device
	device = cache.GetDevice("user@example.com", "not-found")
	assert.Nil(t, device)

	// Non-existent user
	device = cache.GetDevice("other@example.com", "approver-uuid-1")
	assert.Nil(t, device)
}

func TestDeviceKeyCache_ListUsers(t *testing.T) {
	cache := &DeviceKeyCache{
		users: make(map[string]*CachedUser),
	}

	cache.SetUserDevices("alice@example.com", []keyauthapi.DeviceKeyInfo{{ApproverId: "a", AuthPublicKeyHex: "aa", EncryptionPublicKeyHex: "aa"}})
	cache.SetUserDevices("bob@example.com", []keyauthapi.DeviceKeyInfo{{ApproverId: "b", AuthPublicKeyHex: "bb", EncryptionPublicKeyHex: "bb"}})

	users := cache.ListUsers()
	assert.Len(t, users, 2)
	assert.Contains(t, users, "alice@example.com")
	assert.Contains(t, users, "bob@example.com")
}

func TestDeviceKeyCache_RemoveUser(t *testing.T) {
	cache := &DeviceKeyCache{
		users: make(map[string]*CachedUser),
	}

	cache.SetUserDevices("user@example.com", []keyauthapi.DeviceKeyInfo{{ApproverId: "a", AuthPublicKeyHex: "aa", EncryptionPublicKeyHex: "aa"}})
	assert.Len(t, cache.GetUserDevices("user@example.com"), 1)

	cache.RemoveUser("user@example.com")
	assert.Nil(t, cache.GetUserDevices("user@example.com"))
}

func TestDeviceKeyCache_NonExistentFile(t *testing.T) {
	tmpDir := t.TempDir()
	cachePath := filepath.Join(tmpDir, "nonexistent.json")

	cache, err := LoadDeviceKeyCache(cachePath)
	require.NoError(t, err)
	assert.NotNil(t, cache)

	// Should be empty but usable
	assert.Empty(t, cache.ListUsers())
}

func TestDeviceKeyCache_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	cachePath := filepath.Join(tmpDir, "invalid.json")

	err := os.WriteFile(cachePath, []byte("not json"), 0644)
	require.NoError(t, err)

	_, err = LoadDeviceKeyCache(cachePath)
	require.Error(t, err)
}
