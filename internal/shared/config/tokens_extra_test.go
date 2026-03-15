package config

import (
	"testing"
	"time"
)

// ── GetAccessToken error paths (no keyring needed) ───────────────────

func TestProfileConfig_GetAccessToken_NilUserAccount(t *testing.T) {
	p := &ProfileConfig{}
	_, err := p.GetAccessToken()
	if err == nil {
		t.Error("expected error for nil UserAccount")
	}
}

func TestProfileConfig_GetAccessToken_EmptyTokenRef(t *testing.T) {
	p := &ProfileConfig{
		UserAccount: &UserAccount{
			UserID:   "user-1",
			TokenRef: "", // empty
		},
	}
	_, err := p.GetAccessToken()
	if err == nil {
		t.Error("expected error for empty TokenRef")
	}
}

func TestConfig_GetAccessToken_NoActiveProfile(t *testing.T) {
	cfg := &Config{
		ActiveProfile: "nonexistent",
		Profiles:      map[string]*ProfileConfig{},
	}
	_, err := cfg.GetAccessToken()
	if err == nil {
		t.Error("expected error for missing active profile")
	}
}

// ── GetRefreshToken error paths ──────────────────────────────────────

func TestProfileConfig_GetRefreshToken_NilUserAccount(t *testing.T) {
	p := &ProfileConfig{}
	_, err := p.GetRefreshToken()
	if err == nil {
		t.Error("expected error for nil UserAccount")
	}
}

func TestProfileConfig_GetRefreshToken_EmptyRef(t *testing.T) {
	p := &ProfileConfig{
		UserAccount: &UserAccount{
			UserID:          "user-1",
			RefreshTokenRef: "",
		},
	}
	_, err := p.GetRefreshToken()
	if err == nil {
		t.Error("expected error for empty RefreshTokenRef")
	}
}

func TestConfig_GetRefreshToken_NoActiveProfile(t *testing.T) {
	cfg := &Config{
		ActiveProfile: "nonexistent",
		Profiles:      map[string]*ProfileConfig{},
	}
	_, err := cfg.GetRefreshToken()
	if err == nil {
		t.Error("expected error for missing active profile")
	}
}

// ── GetIdentityPrivateKey error paths ────────────────────────────────

func TestProfileConfig_GetIdentityPrivateKey_NilUserAccount(t *testing.T) {
	p := &ProfileConfig{}
	_, err := p.GetIdentityPrivateKey()
	if err == nil {
		t.Error("expected error for nil UserAccount")
	}
}

func TestProfileConfig_GetIdentityPrivateKey_EmptyRef(t *testing.T) {
	p := &ProfileConfig{
		UserAccount: &UserAccount{
			UserID:                "user-1",
			IdentityPrivateKeyRef: "",
		},
	}
	_, err := p.GetIdentityPrivateKey()
	if err == nil {
		t.Error("expected error for empty IdentityPrivateKeyRef")
	}
}

func TestConfig_GetIdentityPrivateKey_NoActiveProfile(t *testing.T) {
	cfg := &Config{
		ActiveProfile: "nonexistent",
		Profiles:      map[string]*ProfileConfig{},
	}
	_, err := cfg.GetIdentityPrivateKey()
	if err == nil {
		t.Error("expected error for missing active profile")
	}
}

// ── UpdateTokens error paths ─────────────────────────────────────────

func TestProfileConfig_UpdateTokens_NilUserAccount(t *testing.T) {
	p := &ProfileConfig{}
	err := p.UpdateTokens("profile", "token", "", time.Now())
	if err == nil {
		t.Error("expected error for nil UserAccount")
	}
}

func TestConfig_UpdateTokens_NoActiveProfile(t *testing.T) {
	cfg := &Config{
		ActiveProfile: "nonexistent",
		Profiles:      map[string]*ProfileConfig{},
	}
	err := cfg.UpdateTokens("token", "", time.Now())
	if err == nil {
		t.Error("expected error for missing active profile")
	}
}

func TestConfig_UpdateTokensForProfile_NoProfile(t *testing.T) {
	cfg := &Config{
		ActiveProfile: "default",
		Profiles:      map[string]*ProfileConfig{},
	}
	err := cfg.UpdateTokensForProfile("nonexistent", "token", "", time.Now())
	if err == nil {
		t.Error("expected error for missing profile")
	}
}

// ── NeedsTokenRefresh ────────────────────────────────────────────────

func TestProfileConfig_NeedsTokenRefresh_NilUserAccount(t *testing.T) {
	p := &ProfileConfig{}
	if p.NeedsTokenRefresh() {
		t.Error("nil UserAccount should not need refresh")
	}
}

func TestProfileConfig_NeedsTokenRefresh_Expired(t *testing.T) {
	p := &ProfileConfig{
		UserAccount: &UserAccount{
			ExpiresAt: time.Now().Add(-1 * time.Hour),
		},
	}
	if !p.NeedsTokenRefresh() {
		t.Error("expired token should need refresh")
	}
}

func TestProfileConfig_NeedsTokenRefresh_ExpiringWithinWeek(t *testing.T) {
	p := &ProfileConfig{
		UserAccount: &UserAccount{
			ExpiresAt: time.Now().Add(3 * 24 * time.Hour), // 3 days
		},
	}
	if !p.NeedsTokenRefresh() {
		t.Error("token expiring within 7 days should need refresh")
	}
}

func TestProfileConfig_NeedsTokenRefresh_Valid(t *testing.T) {
	p := &ProfileConfig{
		UserAccount: &UserAccount{
			ExpiresAt: time.Now().Add(30 * 24 * time.Hour), // 30 days
		},
	}
	if p.NeedsTokenRefresh() {
		t.Error("token valid for 30 days should not need refresh")
	}
}

func TestConfig_NeedsTokenRefresh_NoProfile(t *testing.T) {
	cfg := &Config{
		ActiveProfile: "nonexistent",
		Profiles:      map[string]*ProfileConfig{},
	}
	if cfg.NeedsTokenRefresh() {
		t.Error("missing profile should not need refresh")
	}
}

// ── VerifySASForProfile ──────────────────────────────────────────────

func TestVerifySASForProfile_ValidProfile(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()
	profile, _ := cfg.GetActiveProfile()
	profile.UserAccount = &UserAccount{UserID: "user-1"}

	cfg.VerifySASForProfile(DefaultProfileName)

	if !profile.UserAccount.SASVerified {
		t.Error("SASVerified should be true after VerifySASForProfile")
	}
}

func TestVerifySASForProfile_NoUserAccount(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()
	// No user account set — should not panic
	cfg.VerifySASForProfile(DefaultProfileName)
}

func TestVerifySASForProfile_NoProfile(t *testing.T) {
	cfg := &Config{
		ActiveProfile: "default",
		Profiles:      map[string]*ProfileConfig{},
	}
	// Should not panic for non-existent profile
	cfg.VerifySASForProfile("nonexistent")
}

// ── ClearUserAccount ─────────────────────────────────────────────────

func TestClearUserAccount_NilUserAccount(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()
	// Should not panic when user account is nil
	cfg.ClearUserAccount()
}

func TestClearUserAccount_WithUserAccount(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()
	profile, _ := cfg.GetActiveProfile()
	profile.UserAccount = &UserAccount{
		UserID: "user-1",
		// Empty refs won't hit keyring
		TokenRef:              "",
		RefreshTokenRef:       "",
		IdentityPrivateKeyRef: "",
	}

	cfg.ClearUserAccount()

	if profile.UserAccount != nil {
		t.Error("UserAccount should be nil after ClearUserAccount")
	}
}

func TestConfig_ClearUserAccount_NoActiveProfile(t *testing.T) {
	cfg := &Config{
		ActiveProfile: "nonexistent",
		Profiles:      map[string]*ProfileConfig{},
	}
	// Should not panic
	cfg.ClearUserAccount()
}

// ── GetValidAccessToken ──────────────────────────────────────────────

func TestConfig_GetValidAccessToken_NoActiveProfile(t *testing.T) {
	cfg := &Config{
		ActiveProfile: "nonexistent",
		Profiles:      map[string]*ProfileConfig{},
	}
	_, err := cfg.GetValidAccessToken(nil)
	if err == nil {
		t.Error("expected error for missing active profile")
	}
}

func TestConfig_GetValidAccessToken_NotLoggedIn(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()
	_, err := cfg.GetValidAccessToken(nil)
	if err == nil {
		t.Error("expected error when not logged in")
	}
}
