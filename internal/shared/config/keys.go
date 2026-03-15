package config

// Key management methods for active profile

// FindKey looks up a key by ID, public key hex, or label in the effective org.
// Falls back to profile-level keys if no orgs are configured.
func (c *Config) FindKey(query string) (*KeyMetadata, error) {
	profile, err := c.GetActiveProfile()
	if err != nil {
		return nil, err
	}
	if len(profile.Orgs) > 0 {
		org, err := profile.EffectiveOrg(c.workingOrg)
		if err != nil {
			return nil, err
		}
		return findKeyInSlice(org.Keys, query)
	}
	return profile.FindKey(query)
}

// FindKey looks up a key by ID, public key hex, or label in this profile
func (p *ProfileConfig) FindKey(query string) (*KeyMetadata, error) {
	for i := range p.Keys {
		k := &p.Keys[i]
		keyHex := k.Hex()
		if k.IOSKeyID == query || keyHex == query || k.Label == query {
			return k, nil
		}
		// Also check if query is a suffix of public key hex (e.g., last 8 chars)
		if len(query) < len(keyHex) && keyHex[len(keyHex)-len(query):] == query {
			return k, nil
		}
	}
	return nil, ErrKeyNotFound
}

// AddKey adds or updates a key in the effective org.
// Falls back to profile-level keys if no orgs are configured.
func (c *Config) AddKey(key KeyMetadata) {
	profile, err := c.GetActiveProfile()
	if err != nil {
		return
	}
	if len(profile.Orgs) > 0 {
		org, err := profile.EffectiveOrg(c.workingOrg)
		if err != nil {
			return
		}
		addKeyToSlice(&org.Keys, key)
		return
	}
	profile.AddKey(key)
}

// AddKey adds or updates a key in this profile
func (p *ProfileConfig) AddKey(key KeyMetadata) {
	addKeyToSlice(&p.Keys, key)
}

// RemoveKey removes a key from the effective org.
// Falls back to profile-level keys if no orgs are configured.
func (c *Config) RemoveKey(iosKeyID string) bool {
	profile, err := c.GetActiveProfile()
	if err != nil {
		return false
	}
	if len(profile.Orgs) > 0 {
		org, err := profile.EffectiveOrg(c.workingOrg)
		if err != nil {
			return false
		}
		return removeKeyFromSlice(&org.Keys, iosKeyID)
	}
	return profile.RemoveKey(iosKeyID)
}

// RemoveKey removes a key from this profile
func (p *ProfileConfig) RemoveKey(iosKeyID string) bool {
	for i := range p.Keys {
		if p.Keys[i].IOSKeyID == iosKeyID {
			p.Keys = append(p.Keys[:i], p.Keys[i+1:]...)
			return true
		}
	}
	return false
}

// FindKeyByPurpose finds a key by its purpose (ssh or gpg) in this profile
func (p *ProfileConfig) FindKeyByPurpose(purpose KeyPurpose) *KeyMetadata {
	for i := range p.Keys {
		if p.Keys[i].Purpose == purpose {
			return &p.Keys[i]
		}
	}
	return nil
}

// FindKeyByPurpose finds a key by its purpose (ssh or gpg) in the effective org.
// Falls back to profile-level keys if no orgs are configured.
func (c *Config) FindKeyByPurpose(purpose KeyPurpose) *KeyMetadata {
	profile, err := c.GetActiveProfile()
	if err != nil {
		return nil
	}
	if len(profile.Orgs) > 0 {
		org, err := profile.EffectiveOrg(c.workingOrg)
		if err != nil {
			return nil
		}
		for i := range org.Keys {
			if org.Keys[i].Purpose == purpose {
				return &org.Keys[i]
			}
		}
		return nil
	}
	return profile.FindKeyByPurpose(purpose)
}

// KeysForPurpose returns all keys with the given purpose in this profile
func (p *ProfileConfig) KeysForPurpose(purpose KeyPurpose) []KeyMetadata {
	var result []KeyMetadata
	for _, k := range p.Keys {
		if k.Purpose == purpose {
			result = append(result, k)
		}
	}
	return result
}

// KeysForPurpose returns all keys with the given purpose in the effective org.
// Falls back to profile-level keys if no orgs are configured.
func (c *Config) KeysForPurpose(purpose KeyPurpose) []KeyMetadata {
	profile, err := c.GetActiveProfile()
	if err != nil {
		return nil
	}
	if len(profile.Orgs) > 0 {
		org, err := profile.EffectiveOrg(c.workingOrg)
		if err != nil {
			return nil
		}
		var result []KeyMetadata
		for _, k := range org.Keys {
			if k.Purpose == purpose {
				result = append(result, k)
			}
		}
		return result
	}
	return profile.KeysForPurpose(purpose)
}

// IsLabelUnique checks if a label is unique among keys of the given purpose in this profile
func (p *ProfileConfig) IsLabelUnique(purpose KeyPurpose, label string) bool {
	for _, k := range p.Keys {
		if k.Purpose == purpose && k.Label == label {
			return false
		}
	}
	return true
}

// IsLabelUnique checks if a label is unique among keys of the given purpose in the effective org.
// Falls back to profile-level keys if no orgs are configured.
func (c *Config) IsLabelUnique(purpose KeyPurpose, label string) bool {
	profile, err := c.GetActiveProfile()
	if err != nil {
		return true // No profile means no keys, so label is unique
	}
	if len(profile.Orgs) > 0 {
		org, err := profile.EffectiveOrg(c.workingOrg)
		if err != nil {
			return true
		}
		for _, k := range org.Keys {
			if k.Purpose == purpose && k.Label == label {
				return false
			}
		}
		return true
	}
	return profile.IsLabelUnique(purpose, label)
}

// Keys returns the keys for the effective org in the active profile.
// Falls back to profile-level keys if no orgs are configured.
func (c *Config) Keys() []KeyMetadata {
	profile, err := c.GetActiveProfile()
	if err != nil {
		return nil
	}
	if len(profile.Orgs) > 0 {
		org, err := profile.EffectiveOrg(c.workingOrg)
		if err != nil {
			return nil
		}
		return org.Keys
	}
	return profile.Keys
}

// FindKeyAcrossProfilesAndOrgs searches all profiles and all orgs within each
// for a key by iOS Key ID. Returns the key, the profile name, and any error.
// This is useful for SSH sk-provider which needs to find the correct
// profile for a key regardless of which profile or org is currently active.
func (c *Config) FindKeyAcrossProfilesAndOrgs(iosKeyID string) (*KeyMetadata, string, error) {
	for name, profile := range c.Profiles {
		// Search profile-level keys
		for i := range profile.Keys {
			if profile.Keys[i].IOSKeyID == iosKeyID {
				return &profile.Keys[i], name, nil
			}
		}
		// Search org-level keys
		for oi := range profile.Orgs {
			for ki := range profile.Orgs[oi].Keys {
				if profile.Orgs[oi].Keys[ki].IOSKeyID == iosKeyID {
					return &profile.Orgs[oi].Keys[ki], name, nil
				}
			}
		}
	}
	return nil, "", ErrKeyNotFound
}

// Helper functions for org-scoped key operations

// findKeyInSlice searches a key slice by ID, public key hex, or label.
func findKeyInSlice(keys []KeyMetadata, query string) (*KeyMetadata, error) {
	for i := range keys {
		k := &keys[i]
		keyHex := k.Hex()
		if k.IOSKeyID == query || keyHex == query || k.Label == query {
			return k, nil
		}
		if len(query) < len(keyHex) && keyHex[len(keyHex)-len(query):] == query {
			return k, nil
		}
	}
	return nil, ErrKeyNotFound
}

// addKeyToSlice adds or updates a key in a key slice.
// When IOSKeyID is non-empty, deduplicates by IOSKeyID.
// When IOSKeyID is empty, deduplicates by matching public key + purpose
// to avoid overwriting unrelated keys that also have empty IOSKeyID.
func addKeyToSlice(keys *[]KeyMetadata, key KeyMetadata) {
	for i := range *keys {
		if (*keys)[i].IOSKeyID != "" && (*keys)[i].IOSKeyID == key.IOSKeyID {
			(*keys)[i] = key
			return
		}
		if (*keys)[i].IOSKeyID == "" && key.IOSKeyID == "" &&
			(*keys)[i].Hex() == key.Hex() && (*keys)[i].Purpose == key.Purpose {
			(*keys)[i] = key
			return
		}
	}
	*keys = append(*keys, key)
}

// removeKeyFromSlice removes a key from a key slice by iOS Key ID.
func removeKeyFromSlice(keys *[]KeyMetadata, iosKeyID string) bool {
	for i := range *keys {
		if (*keys)[i].IOSKeyID == iosKeyID {
			*keys = append((*keys)[:i], (*keys)[i+1:]...)
			return true
		}
	}
	return false
}
