package config

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ackagent/cli/internal/shared/tokens"
)

// SetUserAccount stores a new user account for the specified profile.
// Returns an error if credentials cannot be securely stored in the keyring.
func (c *Config) SetUserAccount(profileName string, userID, requesterID, accessToken, refreshToken string, expiresAt time.Time, devices []UserDevice, identityPrivate, identityPublic []byte) error {
	profile, err := c.GetProfile(profileName)
	if err != nil {
		return err
	}

	tokenRef := keyringKey(profileName, "access-token", userID)
	if err := storePrivateKey(tokenRef, []byte(accessToken)); err != nil {
		return fmt.Errorf("%w: failed to store access token: %v", ErrKeyringRequired, err)
	}

	// Store refresh token if provided
	var refreshTokenRef string
	if refreshToken != "" {
		refreshTokenRef = keyringKey(profileName, "refresh-token", userID)
		if err := storePrivateKey(refreshTokenRef, []byte(refreshToken)); err != nil {
			_ = deletePrivateKey(tokenRef)
			return fmt.Errorf("%w: failed to store refresh token: %v", ErrKeyringRequired, err)
		}
	}

	keyRef := keyringKey(profileName, "identity-private", userID)
	if err := storePrivateKey(keyRef, identityPrivate); err != nil {
		// Clean up the tokens we just stored
		_ = deletePrivateKey(tokenRef)
		if refreshTokenRef != "" {
			_ = deletePrivateKey(refreshTokenRef)
		}
		return fmt.Errorf("%w: failed to store identity key: %v", ErrKeyringRequired, err)
	}

	profile.UserAccount = &UserAccount{
		UserID:      userID,
		RequesterID: requesterID,
		// Do NOT store credentials in config - they're in keyring only
		TokenRef:              tokenRef,
		RefreshTokenRef:       refreshTokenRef,
		ExpiresAt:             expiresAt,
		LoggedInAt:            time.Now(),
		SASVerified:           false,
		Devices:               devices,
		IdentityPrivateKeyRef: keyRef,
		IdentityPublicKey:     identityPublic,
	}
	return nil
}

// VerifySASForProfile marks the SAS as verified for the specified profile
func (c *Config) VerifySASForProfile(profileName string) {
	if profile, err := c.GetProfile(profileName); err == nil && profile.UserAccount != nil {
		profile.UserAccount.SASVerified = true
	}
}

// ClearUserAccount removes the current user account from the active profile
func (c *Config) ClearUserAccount() {
	if profile, err := c.GetActiveProfile(); err == nil {
		profile.ClearUserAccount()
	}
}

// ClearUserAccount removes the user account from this profile
func (p *ProfileConfig) ClearUserAccount() {
	if p.UserAccount != nil {
		if p.UserAccount.TokenRef != "" {
			_ = deletePrivateKey(p.UserAccount.TokenRef)
		}
		if p.UserAccount.RefreshTokenRef != "" {
			_ = deletePrivateKey(p.UserAccount.RefreshTokenRef)
		}
		if p.UserAccount.IdentityPrivateKeyRef != "" {
			_ = deletePrivateKey(p.UserAccount.IdentityPrivateKeyRef)
		}
	}
	p.UserAccount = nil
}

// GetAccessToken retrieves the access token from the keyring for the active profile
func (c *Config) GetAccessToken() (string, error) {
	profile, err := c.GetActiveProfile()
	if err != nil {
		return "", err
	}
	return profile.GetAccessToken()
}

// GetAccessToken retrieves the access token from the keyring for this profile
func (p *ProfileConfig) GetAccessToken() (string, error) {
	if p.UserAccount == nil {
		return "", errors.New("not logged in")
	}
	if p.UserAccount.TokenRef == "" {
		return "", errors.New("no token stored")
	}
	tokenBytes, err := loadPrivateKey(p.UserAccount.TokenRef)
	if err != nil {
		return "", fmt.Errorf("failed to load access token from keyring: %w", err)
	}
	return string(tokenBytes), nil
}

// GetValidAccessToken returns a valid access token, refreshing if expired.
// This should be used instead of GetAccessToken() when making API calls.
func (c *Config) GetValidAccessToken(ctx context.Context) (string, error) {
	profile, err := c.GetActiveProfile()
	if err != nil {
		return "", err
	}

	if profile.UserAccount == nil {
		return "", errors.New("not logged in")
	}

	// Check if token is expired or about to expire (within 30 seconds)
	now := time.Now()
	expiresAt := profile.UserAccount.ExpiresAt

	if now.Add(30 * time.Second).After(expiresAt) {
		// Token expired or about to expire, try to refresh
		cfgLog.Debug("token expired/expiring, refreshing...")
		if err := c.refreshTokenForProfile(ctx, profile); err != nil {
			cfgLog.Error("token refresh failed: %v", err)
			return "", fmt.Errorf("token expired and refresh failed: %w", err)
		}
		cfgLog.Debug("token refreshed successfully")
	}

	return profile.GetAccessToken()
}

// refreshTokenForProfile uses the refresh token to get a new access token
func (c *Config) refreshTokenForProfile(ctx context.Context, profile *ProfileConfig) error {
	if profile.IssuerURL == "" {
		return errors.New("issuer URL not configured, cannot refresh token")
	}

	refreshToken, err := profile.GetRefreshToken()
	if err != nil {
		return fmt.Errorf("no refresh token available: %w", err)
	}

	newTokens, err := tokens.RefreshAccessToken(ctx, profile.IssuerURL, refreshToken, "")
	if err != nil {
		return err
	}

	expiresAt := time.Now().Add(time.Duration(newTokens.ExpiresIn) * time.Second)
	if err := profile.UpdateTokens(c.EffectiveProfile(), newTokens.AccessToken, newTokens.RefreshToken, expiresAt); err != nil {
		return fmt.Errorf("failed to store refreshed tokens: %w", err)
	}

	// Save config to persist the new expiration time
	if err := c.Save(); err != nil {
		return fmt.Errorf("failed to save config after token refresh: %w", err)
	}

	return nil
}

// GetRefreshToken retrieves the refresh token from the keyring for the active profile
func (c *Config) GetRefreshToken() (string, error) {
	profile, err := c.GetActiveProfile()
	if err != nil {
		return "", err
	}
	return profile.GetRefreshToken()
}

// GetRefreshToken retrieves the refresh token from the keyring for this profile
func (p *ProfileConfig) GetRefreshToken() (string, error) {
	if p.UserAccount == nil {
		return "", errors.New("not logged in")
	}
	if p.UserAccount.RefreshTokenRef == "" {
		return "", errors.New("no refresh token stored")
	}
	tokenBytes, err := loadPrivateKey(p.UserAccount.RefreshTokenRef)
	if err != nil {
		return "", fmt.Errorf("failed to load refresh token from keyring: %w", err)
	}
	return string(tokenBytes), nil
}

// UpdateTokens updates the stored access and refresh tokens for the active profile
func (c *Config) UpdateTokens(accessToken, refreshToken string, expiresAt time.Time) error {
	profile, err := c.GetActiveProfile()
	if err != nil {
		return err
	}
	return profile.UpdateTokens(c.EffectiveProfile(), accessToken, refreshToken, expiresAt)
}

// UpdateTokensForProfile updates the tokens for a specific profile
func (c *Config) UpdateTokensForProfile(profileName, accessToken, refreshToken string, expiresAt time.Time) error {
	profile, err := c.GetProfile(profileName)
	if err != nil {
		return err
	}
	return profile.UpdateTokens(profileName, accessToken, refreshToken, expiresAt)
}

// UpdateTokens updates the stored access and refresh tokens for this profile
func (p *ProfileConfig) UpdateTokens(profileName, accessToken, refreshToken string, expiresAt time.Time) error {
	if p.UserAccount == nil {
		return errors.New("not logged in")
	}

	// Update access token
	if err := storePrivateKey(p.UserAccount.TokenRef, []byte(accessToken)); err != nil {
		return fmt.Errorf("failed to update access token: %w", err)
	}

	// Update refresh token if provided
	if refreshToken != "" {
		if p.UserAccount.RefreshTokenRef == "" {
			p.UserAccount.RefreshTokenRef = keyringKey(profileName, "refresh-token", p.UserAccount.UserID)
		}
		if err := storePrivateKey(p.UserAccount.RefreshTokenRef, []byte(refreshToken)); err != nil {
			return fmt.Errorf("failed to update refresh token: %w", err)
		}
	}

	p.UserAccount.ExpiresAt = expiresAt
	return nil
}

// NeedsTokenRefresh returns true if the active profile's token should be refreshed
// (expires within 7 days or already expired)
func (c *Config) NeedsTokenRefresh() bool {
	profile, err := c.GetActiveProfile()
	if err != nil {
		return false
	}
	return profile.NeedsTokenRefresh()
}

// NeedsTokenRefresh returns true if the token should be refreshed
func (p *ProfileConfig) NeedsTokenRefresh() bool {
	if p.UserAccount == nil {
		return false
	}
	sevenDays := 7 * 24 * time.Hour
	return time.Until(p.UserAccount.ExpiresAt) < sevenDays
}

// GetIdentityPrivateKey retrieves the identity private key from the keyring for the active profile
func (c *Config) GetIdentityPrivateKey() ([]byte, error) {
	profile, err := c.GetActiveProfile()
	if err != nil {
		return nil, err
	}
	return profile.GetIdentityPrivateKey()
}

// GetIdentityPrivateKey retrieves the identity private key from the keyring for this profile
func (p *ProfileConfig) GetIdentityPrivateKey() ([]byte, error) {
	if p.UserAccount == nil {
		return nil, errors.New("not logged in")
	}
	if p.UserAccount.IdentityPrivateKeyRef == "" {
		return nil, errors.New("no identity key stored")
	}
	return loadPrivateKey(p.UserAccount.IdentityPrivateKeyRef)
}
