package config

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

// Profile Management Methods

// SetWorkingProfile sets the profile to use for operations (overrides active)
// This is typically set via --profile flag or ACKAGENT_PROFILE env var
func (c *Config) SetWorkingProfile(name string) error {
	if _, ok := c.Profiles[name]; !ok {
		return fmt.Errorf("%w: %s", ErrProfileNotFound, name)
	}
	cfgLog.Debug("using profile override: %s (config file active: %s)", name, c.ActiveProfile)
	c.workingProfile = name
	return nil
}

// EffectiveProfile returns the profile name that should be used for operations
// Returns workingProfile if set, otherwise ActiveProfile
func (c *Config) EffectiveProfile() string {
	if c.workingProfile != "" {
		return c.workingProfile
	}
	return c.ActiveProfile
}

// SetWorkingOrg sets the org identifier to use for operations (overrides default).
// This is typically set via --org flag or ACKAGENT_ORG env var.
func (c *Config) SetWorkingOrg(identifier string) {
	c.workingOrg = identifier
}

// WorkingOrg returns the working org override, if any.
func (c *Config) WorkingOrg() string {
	return c.workingOrg
}

// ListProfiles returns all profile names sorted alphabetically
func (c *Config) ListProfiles() []string {
	names := make([]string, 0, len(c.Profiles))
	for name := range c.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// GetProfile returns the specified profile, or the active profile if name is empty
func (c *Config) GetProfile(name string) (*ProfileConfig, error) {
	if name == "" {
		name = c.ActiveProfile
	}
	if name == "" {
		return nil, ErrNoActiveProfile
	}
	profile, ok := c.Profiles[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrProfileNotFound, name)
	}
	return profile, nil
}

// GetActiveProfile returns the effective profile (working profile if set, otherwise active)
func (c *Config) GetActiveProfile() (*ProfileConfig, error) {
	return c.GetProfile(c.EffectiveProfile())
}

// SetActiveProfile switches the active profile
func (c *Config) SetActiveProfile(name string) error {
	if _, ok := c.Profiles[name]; !ok {
		return fmt.Errorf("%w: %s", ErrProfileNotFound, name)
	}
	c.ActiveProfile = name
	return nil
}

// CreateProfile creates a new profile with the given name
func (c *Config) CreateProfile(name, relayURL, issuerURL string) error {
	if _, ok := c.Profiles[name]; ok {
		return fmt.Errorf("%w: %s", ErrProfileExists, name)
	}
	c.Profiles[name] = &ProfileConfig{
		RelayURL:  relayURL,
		IssuerURL: issuerURL,
		Keys:      []KeyMetadata{},
	}
	return nil
}

// DeleteProfile removes a profile, its file, and its keyring credentials
func (c *Config) DeleteProfile(name string) error {
	profile, ok := c.Profiles[name]
	if !ok {
		return fmt.Errorf("%w: %s", ErrProfileNotFound, name)
	}
	if len(c.Profiles) <= 1 {
		return ErrCannotDeleteLast
	}

	// Clean up keyring entries
	if profile.UserAccount != nil {
		if profile.UserAccount.TokenRef != "" {
			_ = deletePrivateKey(profile.UserAccount.TokenRef)
		}
		if profile.UserAccount.RefreshTokenRef != "" {
			_ = deletePrivateKey(profile.UserAccount.RefreshTokenRef)
		}
		if profile.UserAccount.IdentityPrivateKeyRef != "" {
			_ = deletePrivateKey(profile.UserAccount.IdentityPrivateKeyRef)
		}
	}

	// Delete the profile file
	if err := deleteProfileFile(name); err != nil && !os.IsNotExist(err) {
		cfgLog.Warn("failed to delete profile file %s: %v", name, err)
	}

	delete(c.Profiles, name)

	// If we deleted the active profile, switch to another
	if c.ActiveProfile == name {
		for newName := range c.Profiles {
			c.ActiveProfile = newName
			break
		}
	}

	return nil
}

// RenameProfile renames a profile, updating keyring keys
func (c *Config) RenameProfile(oldName, newName string) error {
	if oldName == newName {
		return nil
	}
	profile, ok := c.Profiles[oldName]
	if !ok {
		return fmt.Errorf("%w: %s", ErrProfileNotFound, oldName)
	}
	if _, ok := c.Profiles[newName]; ok {
		return fmt.Errorf("%w: %s", ErrProfileExists, newName)
	}

	// Migrate keyring keys if there's a user account
	if profile.UserAccount != nil {
		userID := profile.UserAccount.UserID

		// Migrate access token
		if profile.UserAccount.TokenRef != "" {
			newRef := keyringKey(newName, "access-token", userID)
			if err := migrateKeyringKey(profile.UserAccount.TokenRef, newRef); err == nil {
				profile.UserAccount.TokenRef = newRef
			}
		}

		// Migrate refresh token
		if profile.UserAccount.RefreshTokenRef != "" {
			newRef := keyringKey(newName, "refresh-token", userID)
			if err := migrateKeyringKey(profile.UserAccount.RefreshTokenRef, newRef); err == nil {
				profile.UserAccount.RefreshTokenRef = newRef
			}
		}

		// Migrate identity key
		if profile.UserAccount.IdentityPrivateKeyRef != "" {
			newRef := keyringKey(newName, "identity-private", userID)
			if err := migrateKeyringKey(profile.UserAccount.IdentityPrivateKeyRef, newRef); err == nil {
				profile.UserAccount.IdentityPrivateKeyRef = newRef
			}
		}
	}

	// Move profile to new name in memory
	c.Profiles[newName] = profile
	delete(c.Profiles, oldName)

	// Rename the profile file: save new file, delete old file
	if err := saveProfileFile(newName, profile); err != nil {
		// Rollback in-memory change
		c.Profiles[oldName] = profile
		delete(c.Profiles, newName)
		return fmt.Errorf("failed to save renamed profile: %w", err)
	}
	if err := deleteProfileFile(oldName); err != nil && !os.IsNotExist(err) {
		cfgLog.Warn("failed to delete old profile file %s: %v", oldName, err)
	}

	// Update active profile if it was renamed
	if c.ActiveProfile == oldName {
		c.ActiveProfile = newName
	}

	return nil
}

// ResolveOrg finds an org by UUID, local name (case-insensitive), or emoji words.
func (p *ProfileConfig) ResolveOrg(identifier string) (*OrgConfig, error) {
	if len(p.Orgs) == 0 {
		return nil, ErrNoOrgs
	}

	lower := strings.ToLower(identifier)
	for i := range p.Orgs {
		o := &p.Orgs[i]
		// Match by org ID (exact)
		if o.OrgID == identifier {
			return o, nil
		}
		// Match by local name (case-insensitive)
		if o.LocalName != "" && strings.ToLower(o.LocalName) == lower {
			return o, nil
		}
		// Match by emoji words (case-insensitive)
		if strings.ToLower(o.EmojiWords()) == lower {
			return o, nil
		}
	}

	return nil, fmt.Errorf("%w: %s", ErrOrgNotFound, identifier)
}

// EffectiveOrg returns the active org using the priority chain:
// --org flag > ACKAGENT_ORG env > DefaultOrgID > single-org auto-select.
// The override parameter is the value from --org flag or ACKAGENT_ORG env var.
func (p *ProfileConfig) EffectiveOrg(override string) (*OrgConfig, error) {
	if len(p.Orgs) == 0 {
		return nil, ErrNoOrgs
	}

	// Priority 1: explicit override (--org flag or ACKAGENT_ORG env)
	if override != "" {
		return p.ResolveOrg(override)
	}

	// Priority 2: configured default org
	if p.DefaultOrgID != "" {
		return p.ResolveOrg(p.DefaultOrgID)
	}

	// Priority 3: auto-select if exactly one org
	if len(p.Orgs) == 1 {
		return &p.Orgs[0], nil
	}

	// Multiple orgs, no default or override set
	return nil, ErrOrgRequired
}

// FindOrg returns the org with the given ID, or nil if not found.
func (p *ProfileConfig) FindOrg(orgID string) *OrgConfig {
	for i := range p.Orgs {
		if p.Orgs[i].OrgID == orgID {
			return &p.Orgs[i]
		}
	}
	return nil
}

// AddOrg adds or updates an organization in this profile.
func (p *ProfileConfig) AddOrg(org OrgConfig) {
	for i := range p.Orgs {
		if p.Orgs[i].OrgID == org.OrgID {
			p.Orgs[i] = org
			return
		}
	}
	p.Orgs = append(p.Orgs, org)
}

// IsLoggedIn returns true if the active profile is logged into a user account with verified SAS
func (c *Config) IsLoggedIn() bool {
	profile, err := c.GetActiveProfile()
	if err != nil {
		return false
	}
	return profile.IsLoggedIn()
}

// Convenience accessors for active profile fields

// RelayURL returns the backend URL for the active profile
func (c *Config) RelayURL() string {
	profile, err := c.GetActiveProfile()
	if err != nil {
		return ""
	}
	return profile.RelayURL
}

// IssuerURL returns the OIDC issuer URL for the active profile
func (c *Config) IssuerURL() string {
	profile, err := c.GetActiveProfile()
	if err != nil {
		return ""
	}
	return profile.IssuerURL
}

// UserAccount returns the user account for the active profile
func (c *Config) UserAccount() *UserAccount {
	profile, err := c.GetActiveProfile()
	if err != nil {
		return nil
	}
	return profile.UserAccount
}

// HookSettings returns the hook settings for the active profile
func (c *Config) HookSettings() *HookSettings {
	profile, err := c.GetActiveProfile()
	if err != nil {
		return nil
	}
	return profile.HookSettings
}

// SetHookSettings sets the hook settings for the active profile
func (c *Config) SetHookSettings(settings *HookSettings) {
	profile, err := c.GetActiveProfile()
	if err != nil {
		return
	}
	profile.HookSettings = settings
}

// EffectiveOrgForProfile returns the effective org for the active profile,
// using the Config's workingOrg override. Returns nil if no orgs are configured.
func (c *Config) EffectiveOrgForProfile() (*OrgConfig, error) {
	profile, err := c.GetActiveProfile()
	if err != nil {
		return nil, err
	}
	if len(profile.Orgs) == 0 {
		return nil, ErrNoOrgs
	}
	return profile.EffectiveOrg(c.workingOrg)
}
