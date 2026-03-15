package attestation

import (
	"context"
	"fmt"

	authapi "github.com/ackagent/api/go/auth"
	"github.com/ackagent/cli/internal/shared/client"
	"github.com/ackagent/cli/internal/shared/config"
)

// EnsureIssuerPublicKey ensures the effective profile has a cached BBS+ issuer
// public key used to verify anonymous attestations.
func EnsureIssuerPublicKey(
	ctx context.Context,
	cfg *config.Config,
	accessToken string,
) ([]byte, error) {
	return EnsureIssuerPublicKeyForProfile(ctx, cfg, cfg.EffectiveProfile(), accessToken)
}

// EnsureIssuerPublicKeyForProfile ensures the specified profile has a cached
// BBS+ issuer public key used to verify anonymous attestations.
//
// If the key is missing, this function fetches all keys from
// /api/v1/credentials/public-key, selects the best one, and persists both
// the key and its ID in config.
func EnsureIssuerPublicKeyForProfile(
	ctx context.Context,
	cfg *config.Config,
	profileName string,
	accessToken string,
) ([]byte, error) {
	profile, err := cfg.GetProfile(profileName)
	if err != nil {
		return nil, fmt.Errorf("load profile %q: %w", profileName, err)
	}

	if len(profile.IssuerPublicKey) > 0 {
		return append([]byte(nil), profile.IssuerPublicKey...), nil
	}

	if profile.IssuerURL == "" {
		return nil, fmt.Errorf("profile %q missing issuer URL", profileName)
	}

	authClient, err := client.NewClient(profile.IssuerURL, cfg.DeviceID)
	if err != nil {
		return nil, fmt.Errorf("create auth client: %w", err)
	}
	authClient.SetAccessToken(accessToken)

	allKeys, err := authClient.GetAllCredentialIssuerPublicKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch credential issuer public keys: %w", err)
	}

	selected := selectBestIssuerKey(allKeys)
	if selected == nil {
		return nil, fmt.Errorf("no usable credential issuer public key returned")
	}

	profile.IssuerPublicKey = append([]byte(nil), selected.PublicKey...)
	profile.IssuerPublicKeyID = selected.Id
	if err := cfg.Save(); err != nil {
		return nil, fmt.Errorf("persist issuer public key: %w", err)
	}

	return append([]byte(nil), selected.PublicKey...), nil
}

// FetchAllIssuerPublicKeys fetches all readable issuer public keys from the credential-issuer service.
// Always fetches fresh (no caching) — used during verification fallback.
func FetchAllIssuerPublicKeys(ctx context.Context, cfg *config.Config, accessToken string) ([]authapi.IssuerPublicKeyInfo, error) {
	profile, err := cfg.GetActiveProfile()
	if err != nil {
		return nil, fmt.Errorf("get active profile: %w", err)
	}

	if profile.IssuerURL == "" {
		return nil, fmt.Errorf("active profile missing issuer URL")
	}

	authClient, err := client.NewClient(profile.IssuerURL, cfg.DeviceID)
	if err != nil {
		return nil, fmt.Errorf("create auth client: %w", err)
	}
	authClient.SetAccessToken(accessToken)

	return authClient.GetAllCredentialIssuerPublicKeys(ctx)
}

// selectBestIssuerKey selects the best issuer key from a list:
// 1. Prefer the newest non-rotated key.
// 2. If all keys are rotated, fall back to the newest key.
func selectBestIssuerKey(keys []authapi.IssuerPublicKeyInfo) *authapi.IssuerPublicKeyInfo {
	var newestActive *authapi.IssuerPublicKeyInfo
	var newestAny *authapi.IssuerPublicKeyInfo

	for i := range keys {
		key := &keys[i]
		if len(key.PublicKey) == 0 {
			continue
		}

		if newestAny == nil || key.CreatedAt.After(newestAny.CreatedAt) {
			newestAny = key
		}
		if key.RotatedAt == nil &&
			(newestActive == nil || key.CreatedAt.After(newestActive.CreatedAt)) {
			newestActive = key
		}
	}

	if newestActive != nil {
		return newestActive
	}
	return newestAny
}
