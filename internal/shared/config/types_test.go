package config

import (
	"testing"
	"time"
)

func TestKeyMetadata_IsHardwareBacked(t *testing.T) {
	tests := []struct {
		storage KeyStorageType
		want    bool
	}{
		{StorageTypeSecureEnclave, true},
		{StorageTypeICloudKeychain, false},
		{StorageTypeSoftwareLocal, false},
		{"", false},
	}
	for _, tt := range tests {
		k := KeyMetadata{StorageType: tt.storage}
		if got := k.IsHardwareBacked(); got != tt.want {
			t.Errorf("IsHardwareBacked(%q) = %v, want %v", tt.storage, got, tt.want)
		}
	}
}

func TestKeyMetadata_IsSyncable(t *testing.T) {
	tests := []struct {
		storage KeyStorageType
		want    bool
	}{
		{StorageTypeICloudKeychain, true},
		{StorageTypeSecureEnclave, false},
		{StorageTypeSoftwareLocal, false},
		{"", false},
	}
	for _, tt := range tests {
		k := KeyMetadata{StorageType: tt.storage}
		if got := k.IsSyncable(); got != tt.want {
			t.Errorf("IsSyncable(%q) = %v, want %v", tt.storage, got, tt.want)
		}
	}
}

func TestKeyMetadata_IsEd25519(t *testing.T) {
	tests := []struct {
		algo string
		want bool
	}{
		{AlgorithmEd25519, true},
		{AlgorithmP256, false},
		{AlgorithmX25519, false},
		{"", false},
	}
	for _, tt := range tests {
		k := KeyMetadata{Algorithm: tt.algo}
		if got := k.IsEd25519(); got != tt.want {
			t.Errorf("IsEd25519(%q) = %v, want %v", tt.algo, got, tt.want)
		}
	}
}

func TestKeyMetadata_IsP256(t *testing.T) {
	tests := []struct {
		algo string
		want bool
	}{
		{AlgorithmP256, true},
		{"", true}, // empty defaults to P-256
		{AlgorithmEd25519, false},
		{AlgorithmX25519, false},
	}
	for _, tt := range tests {
		k := KeyMetadata{Algorithm: tt.algo}
		if got := k.IsP256(); got != tt.want {
			t.Errorf("IsP256(%q) = %v, want %v", tt.algo, got, tt.want)
		}
	}
}

func TestKeyMetadata_IsX25519(t *testing.T) {
	tests := []struct {
		algo string
		want bool
	}{
		{AlgorithmX25519, true},
		{AlgorithmP256, false},
		{AlgorithmEd25519, false},
		{"", false},
	}
	for _, tt := range tests {
		k := KeyMetadata{Algorithm: tt.algo}
		if got := k.IsX25519(); got != tt.want {
			t.Errorf("IsX25519(%q) = %v, want %v", tt.algo, got, tt.want)
		}
	}
}

func TestKeyMetadata_PublicKeySize(t *testing.T) {
	tests := []struct {
		algo string
		want int
	}{
		{AlgorithmP256, 33},
		{"", 33},
		{AlgorithmEd25519, 32},
		{AlgorithmX25519, 32},
	}
	for _, tt := range tests {
		k := KeyMetadata{Algorithm: tt.algo}
		if got := k.PublicKeySize(); got != tt.want {
			t.Errorf("PublicKeySize(%q) = %d, want %d", tt.algo, got, tt.want)
		}
	}
}

func TestKeyMetadata_Hex(t *testing.T) {
	k := KeyMetadata{PublicKey: []byte{0xab, 0xcd, 0xef}}
	if got := k.Hex(); got != "abcdef" {
		t.Errorf("Hex() = %q, want %q", got, "abcdef")
	}

	empty := KeyMetadata{}
	if got := empty.Hex(); got != "" {
		t.Errorf("Hex() on empty key = %q, want %q", got, "")
	}
}

func TestKeyMetadata_HasEncryptionSubkey(t *testing.T) {
	tests := []struct {
		name        string
		encPubKey   []byte
		encFingerpr string
		want        bool
	}{
		{"both present", []byte{0x01}, "abc123", true},
		{"no pubkey", nil, "abc123", false},
		{"no fingerprint", []byte{0x01}, "", false},
		{"neither", nil, "", false},
		{"empty pubkey", []byte{}, "abc123", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := KeyMetadata{
				EncryptionPublicKey:   tt.encPubKey,
				EncryptionFingerprint: tt.encFingerpr,
			}
			if got := k.HasEncryptionSubkey(); got != tt.want {
				t.Errorf("HasEncryptionSubkey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKeyMetadata_EffectiveEncryptionPublicKey(t *testing.T) {
	primaryKey := []byte{0x01, 0x02}
	encKey := []byte{0x03, 0x04}

	// With subkey
	k := KeyMetadata{
		PublicKey:             primaryKey,
		EncryptionPublicKey:   encKey,
		EncryptionFingerprint: "abc",
	}
	result := k.EffectiveEncryptionPublicKey()
	if string(result) != string(encKey) {
		t.Error("should return encryption subkey when present")
	}

	// Without subkey
	k2 := KeyMetadata{PublicKey: primaryKey}
	result = k2.EffectiveEncryptionPublicKey()
	if string(result) != string(primaryKey) {
		t.Error("should return primary key when no subkey")
	}
}

func TestKeyMetadata_EffectiveEncryptionFingerprint(t *testing.T) {
	k := KeyMetadata{
		PublicKey:             []byte{0xab, 0xcd},
		EncryptionPublicKey:   []byte{0x01},
		EncryptionFingerprint: "subkey-fp",
	}
	if got := k.EffectiveEncryptionFingerprint(); got != "subkey-fp" {
		t.Errorf("EffectiveEncryptionFingerprint() = %q, want subkey-fp", got)
	}

	k2 := KeyMetadata{PublicKey: []byte{0xab, 0xcd}}
	if got := k2.EffectiveEncryptionFingerprint(); got != "abcd" {
		t.Errorf("EffectiveEncryptionFingerprint() = %q, want abcd", got)
	}
}

func TestValidateProfileName(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{"default", false},
		{"my-profile", false},
		{"my_profile", false},
		{"Profile123", false},
		{"a", false},
		{"", true},
		{"-invalid", true},
		{"_invalid", true},
		{"has space", true},
		{"has.dot", true},
		{"has/slash", true},
		{"123starts-with-number", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateProfileName(tt.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateProfileName(%q) error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}
		})
	}
}

func TestProfileConfig_IsLoggedIn(t *testing.T) {
	tests := []struct {
		name    string
		profile ProfileConfig
		want    bool
	}{
		{"nil account", ProfileConfig{}, false},
		{"unverified SAS", ProfileConfig{
			UserAccount: &UserAccount{SASVerified: false},
		}, false},
		{"verified but no devices", ProfileConfig{
			UserAccount: &UserAccount{SASVerified: true},
		}, false},
		{"fully logged in", ProfileConfig{
			UserAccount: &UserAccount{
				SASVerified: true,
				Devices:     []UserDevice{{ApproverId: "test"}},
			},
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.profile.IsLoggedIn(); got != tt.want {
				t.Errorf("IsLoggedIn() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProfileConfig_FindKeyByPurpose(t *testing.T) {
	p := &ProfileConfig{
		Keys: []KeyMetadata{
			{IOSKeyID: "ssh-1", Purpose: KeyPurposeSSH},
			{IOSKeyID: "gpg-1", Purpose: KeyPurposeGPG},
			{IOSKeyID: "ssh-2", Purpose: KeyPurposeSSH},
		},
	}

	// Finds first SSH key
	k := p.FindKeyByPurpose(KeyPurposeSSH)
	if k == nil || k.IOSKeyID != "ssh-1" {
		t.Errorf("FindKeyByPurpose(SSH) = %v, want ssh-1", k)
	}

	// Finds GPG key
	k = p.FindKeyByPurpose(KeyPurposeGPG)
	if k == nil || k.IOSKeyID != "gpg-1" {
		t.Errorf("FindKeyByPurpose(GPG) = %v, want gpg-1", k)
	}

	// Returns nil for Age (not present)
	k = p.FindKeyByPurpose(KeyPurposeAge)
	if k != nil {
		t.Errorf("FindKeyByPurpose(Age) = %v, want nil", k)
	}
}

func TestProfileConfig_FindKey(t *testing.T) {
	p := &ProfileConfig{
		Keys: []KeyMetadata{
			{IOSKeyID: "key-1", Label: "My Key", PublicKey: []byte{0xab, 0xcd, 0xef}},
		},
	}

	tests := []struct {
		query   string
		wantID  string
		wantErr bool
	}{
		{"key-1", "key-1", false},
		{"My Key", "key-1", false},
		{"abcdef", "key-1", false},
		{"ef", "key-1", false}, // suffix match
		{"nonexistent", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			k, err := p.FindKey(tt.query)
			if tt.wantErr {
				if err == nil {
					t.Errorf("FindKey(%q) should return error", tt.query)
				}
			} else {
				if err != nil {
					t.Errorf("FindKey(%q) error = %v", tt.query, err)
				} else if k.IOSKeyID != tt.wantID {
					t.Errorf("FindKey(%q) = %s, want %s", tt.query, k.IOSKeyID, tt.wantID)
				}
			}
		})
	}
}

func TestProfileConfig_RemoveKey(t *testing.T) {
	p := &ProfileConfig{
		Keys: []KeyMetadata{
			{IOSKeyID: "key-1"},
			{IOSKeyID: "key-2"},
		},
	}

	if !p.RemoveKey("key-1") {
		t.Error("RemoveKey should return true for existing key")
	}
	if len(p.Keys) != 1 {
		t.Errorf("len(Keys) = %d, want 1", len(p.Keys))
	}

	if p.RemoveKey("nonexistent") {
		t.Error("RemoveKey should return false for nonexistent key")
	}
}

func TestProfileConfig_KeysForPurpose(t *testing.T) {
	p := &ProfileConfig{
		Keys: []KeyMetadata{
			{IOSKeyID: "ssh-1", Purpose: KeyPurposeSSH},
			{IOSKeyID: "gpg-1", Purpose: KeyPurposeGPG},
			{IOSKeyID: "ssh-2", Purpose: KeyPurposeSSH},
		},
	}

	sshKeys := p.KeysForPurpose(KeyPurposeSSH)
	if len(sshKeys) != 2 {
		t.Errorf("KeysForPurpose(SSH) count = %d, want 2", len(sshKeys))
	}

	gpgKeys := p.KeysForPurpose(KeyPurposeGPG)
	if len(gpgKeys) != 1 {
		t.Errorf("KeysForPurpose(GPG) count = %d, want 1", len(gpgKeys))
	}

	ageKeys := p.KeysForPurpose(KeyPurposeAge)
	if len(ageKeys) != 0 {
		t.Errorf("KeysForPurpose(Age) count = %d, want 0", len(ageKeys))
	}
}

func TestProfileConfig_IsLabelUnique(t *testing.T) {
	p := &ProfileConfig{
		Keys: []KeyMetadata{
			{IOSKeyID: "ssh-1", Purpose: KeyPurposeSSH, Label: "work"},
		},
	}

	if p.IsLabelUnique(KeyPurposeSSH, "work") {
		t.Error("should not be unique for existing label")
	}
	if !p.IsLabelUnique(KeyPurposeSSH, "personal") {
		t.Error("should be unique for new label")
	}
	if !p.IsLabelUnique(KeyPurposeGPG, "work") {
		t.Error("should be unique for different purpose")
	}
}

func TestConfig_WorkingProfile(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()
	cfg.CreateProfile("other", "http://test", "http://auth")

	// Default effective profile is active profile
	if cfg.EffectiveProfile() != DefaultProfileName {
		t.Errorf("EffectiveProfile() = %q, want %q", cfg.EffectiveProfile(), DefaultProfileName)
	}

	// Set working profile override
	if err := cfg.SetWorkingProfile("other"); err != nil {
		t.Fatalf("SetWorkingProfile() error = %v", err)
	}
	if cfg.EffectiveProfile() != "other" {
		t.Errorf("EffectiveProfile() = %q, want other", cfg.EffectiveProfile())
	}

	// Invalid profile
	if err := cfg.SetWorkingProfile("nonexistent"); err == nil {
		t.Error("SetWorkingProfile should fail for nonexistent profile")
	}
}

func TestConfig_WorkingOrg(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()

	if cfg.WorkingOrg() != "" {
		t.Error("WorkingOrg should default to empty")
	}

	cfg.SetWorkingOrg("org-123")
	if cfg.WorkingOrg() != "org-123" {
		t.Errorf("WorkingOrg() = %q, want org-123", cfg.WorkingOrg())
	}
}

func TestConfig_ConvenienceAccessors(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()
	p, _ := cfg.GetActiveProfile()
	p.RelayURL = "https://relay.test"
	p.IssuerURL = "https://issuer.test"

	if cfg.RelayURL() != "https://relay.test" {
		t.Errorf("RelayURL() = %q", cfg.RelayURL())
	}
	if cfg.IssuerURL() != "https://issuer.test" {
		t.Errorf("IssuerURL() = %q", cfg.IssuerURL())
	}
	if cfg.UserAccount() != nil {
		t.Error("UserAccount() should be nil when not logged in")
	}
	if cfg.HookSettings() != nil {
		t.Error("HookSettings() should be nil by default")
	}
}

func TestConfig_SetHookSettings(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()

	settings := &HookSettings{
		FilteredTools:  []string{"Bash"},
		TimeoutSeconds: 60,
	}
	cfg.SetHookSettings(settings)

	got := cfg.HookSettings()
	if got == nil {
		t.Fatal("HookSettings() returned nil after set")
	}
	if got.TimeoutSeconds != 60 {
		t.Errorf("TimeoutSeconds = %d, want 60", got.TimeoutSeconds)
	}
}

func TestProfileConfig_NeedsTokenRefresh(t *testing.T) {
	tests := []struct {
		name    string
		profile ProfileConfig
		want    bool
	}{
		{"nil account", ProfileConfig{}, false},
		{"token not expiring", ProfileConfig{
			UserAccount: &UserAccount{
				ExpiresAt: timeInFuture(30 * 24),
			},
		}, false},
		{"token expiring within 7 days", ProfileConfig{
			UserAccount: &UserAccount{
				ExpiresAt: timeInFuture(3 * 24),
			},
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.profile.NeedsTokenRefresh(); got != tt.want {
				t.Errorf("NeedsTokenRefresh() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProfileConfig_GetAccessToken_NotLoggedIn(t *testing.T) {
	p := &ProfileConfig{}
	_, err := p.GetAccessToken()
	if err == nil {
		t.Error("GetAccessToken should fail when not logged in")
	}
}

func TestProfileConfig_GetAccessToken_NoTokenRef(t *testing.T) {
	p := &ProfileConfig{
		UserAccount: &UserAccount{UserID: "user-1"},
	}
	_, err := p.GetAccessToken()
	if err == nil {
		t.Error("GetAccessToken should fail when no token ref")
	}
}

func TestProfileConfig_GetRefreshToken_NotLoggedIn(t *testing.T) {
	p := &ProfileConfig{}
	_, err := p.GetRefreshToken()
	if err == nil {
		t.Error("GetRefreshToken should fail when not logged in")
	}
}

func TestProfileConfig_GetRefreshToken_NoRef(t *testing.T) {
	p := &ProfileConfig{
		UserAccount: &UserAccount{UserID: "user-1"},
	}
	_, err := p.GetRefreshToken()
	if err == nil {
		t.Error("GetRefreshToken should fail when no refresh token ref")
	}
}

func TestProfileConfig_GetIdentityPrivateKey_NotLoggedIn(t *testing.T) {
	p := &ProfileConfig{}
	_, err := p.GetIdentityPrivateKey()
	if err == nil {
		t.Error("GetIdentityPrivateKey should fail when not logged in")
	}
}

func TestProfileConfig_GetIdentityPrivateKey_NoRef(t *testing.T) {
	p := &ProfileConfig{
		UserAccount: &UserAccount{UserID: "user-1"},
	}
	_, err := p.GetIdentityPrivateKey()
	if err == nil {
		t.Error("GetIdentityPrivateKey should fail when no identity key ref")
	}
}

func TestProfileConfig_UpdateTokens_NotLoggedIn(t *testing.T) {
	p := &ProfileConfig{}
	err := p.UpdateTokens("default", "token", "", timeInFuture(1))
	if err == nil {
		t.Error("UpdateTokens should fail when not logged in")
	}
}

func TestConfig_GetProfile_Empty(t *testing.T) {
	cfg := &Config{
		Profiles: make(map[string]*ProfileConfig),
	}
	_, err := cfg.GetProfile("")
	if err != ErrNoActiveProfile {
		t.Errorf("GetProfile(\"\") with empty ActiveProfile should return ErrNoActiveProfile, got: %v", err)
	}
}

func TestFindOrg(t *testing.T) {
	p := &ProfileConfig{
		Orgs: []OrgConfig{
			{OrgID: "org-1"},
			{OrgID: "org-2"},
		},
	}

	org := p.FindOrg("org-1")
	if org == nil || org.OrgID != "org-1" {
		t.Error("FindOrg should find org-1")
	}

	org = p.FindOrg("nonexistent")
	if org != nil {
		t.Error("FindOrg should return nil for nonexistent org")
	}
}

// timeInFuture returns a time N hours in the future.
func timeInFuture(hours int) time.Time {
	return time.Now().Add(time.Duration(hours) * time.Hour)
}
