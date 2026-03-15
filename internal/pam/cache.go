package pam

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	keyauthapi "github.com/ackagent/api/go/keyauth"
)

// CachedUser represents cached device keys for a user.
type CachedUser struct {
	// Email is the user's AckAgent email.
	Email string `json:"email"`
	// Devices is the list of device keys for this user (uses keyauth generated type).
	Devices []keyauthapi.DeviceKeyInfo `json:"devices"`
	// SyncedAt is when this user's keys were last synced.
	SyncedAt time.Time `json:"synced_at"`
}

// cacheFile represents the cache file structure.
type cacheFile struct {
	Version int                    `json:"version"`
	OrgID   string                 `json:"org_id"`
	Users   map[string]*CachedUser `json:"users"` // key: email
}

// DeviceKeyCache manages cached device keys for offline operation.
type DeviceKeyCache struct {
	mu      sync.RWMutex
	path    string
	version int
	orgID   string
	users   map[string]*CachedUser
}

const cacheVersion = 1

// LoadDeviceKeyCache loads a device key cache from file.
func LoadDeviceKeyCache(path string) (*DeviceKeyCache, error) {
	cache := &DeviceKeyCache{
		path:    path,
		version: cacheVersion,
		users:   make(map[string]*CachedUser),
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Empty cache is fine
			return cache, nil
		}
		return nil, fmt.Errorf("failed to read cache file: %w", err)
	}

	var file cacheFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("failed to parse cache file: %w", err)
	}

	if file.Version > cacheVersion {
		return nil, fmt.Errorf("cache version %d is newer than supported version %d", file.Version, cacheVersion)
	}

	cache.orgID = file.OrgID
	cache.users = file.Users
	if cache.users == nil {
		cache.users = make(map[string]*CachedUser)
	}

	return cache, nil
}

// Save writes the cache to disk.
func (c *DeviceKeyCache) Save() error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	file := cacheFile{
		Version: c.version,
		OrgID:   c.orgID,
		Users:   c.users,
	}

	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal cache: %w", err)
	}

	// Ensure directory exists
	dir := filepath.Dir(c.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	// Write atomically
	tmpPath := c.path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write cache file: %w", err)
	}

	if err := os.Rename(tmpPath, c.path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to rename cache file: %w", err)
	}

	return nil
}

// SetOrgID sets the organization ID.
func (c *DeviceKeyCache) SetOrgID(orgID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.orgID = orgID
}

// GetUserDevices returns the cached devices for a user.
func (c *DeviceKeyCache) GetUserDevices(email string) []keyauthapi.DeviceKeyInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	user, ok := c.users[email]
	if !ok {
		return nil
	}

	return user.Devices
}

// GetDevice returns a specific device from the cache by approver ID.
func (c *DeviceKeyCache) GetDevice(email, approverId string) *keyauthapi.DeviceKeyInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	user, ok := c.users[email]
	if !ok {
		return nil
	}

	for i := range user.Devices {
		if user.Devices[i].ApproverId == approverId {
			return &user.Devices[i]
		}
	}

	return nil
}

// SetUserDevices sets the cached devices for a user.
func (c *DeviceKeyCache) SetUserDevices(email string, devices []keyauthapi.DeviceKeyInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.users[email] = &CachedUser{
		Email:    email,
		Devices:  devices,
		SyncedAt: time.Now(),
	}
}

// RemoveUser removes a user from the cache.
func (c *DeviceKeyCache) RemoveUser(email string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.users, email)
}

// ListUsers returns all cached user emails.
func (c *DeviceKeyCache) ListUsers() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	users := make([]string, 0, len(c.users))
	for email := range c.users {
		users = append(users, email)
	}
	return users
}
