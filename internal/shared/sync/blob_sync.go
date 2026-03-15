package sync

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ackagent/cli/crypto"
	"github.com/ackagent/cli/internal/shared/client"
	"github.com/ackagent/cli/internal/shared/config"
)

// KeyMetadataBlob is the structure stored in the encrypted blob.
// This is what gets encrypted/decrypted - the server never sees this.
type KeyMetadataBlob struct {
	Keys      []config.KeyMetadata `json:"keys"`
	UpdatedAt time.Time            `json:"updatedAt"`
}

// syncKeyMetadata fetches and decrypts key metadata from the blob service.
func syncKeyMetadata(
	ctx context.Context,
	cfg *config.Config,
	accessToken string,
	opts SyncOptions,
) ([]SyncedKey, error) {
	profile, err := cfg.GetActiveProfile()
	if err != nil {
		return nil, fmt.Errorf("no active profile: %w", err)
	}

	blobURL := opts.BlobURL
	if blobURL == "" {
		if profile.BlobURL != "" {
			blobURL = profile.BlobURL
		} else {
			blobURL = config.LocalDev.BlobURL
		}
	}

	blobClient, err := client.NewBlobClient(blobURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create blob client: %w", err)
	}

	if len(profile.Orgs) > 0 {
		org, orgErr := profile.EffectiveOrg(cfg.WorkingOrg())
		if orgErr == nil {
			blobClient.OrgID = org.OrgID
		}
	}

	blobResult, err := blobClient.GetBlob(ctx, accessToken)
	if err != nil {
		return nil, err
	}

	identityPrivate, err := profile.GetIdentityPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get identity private key: %w", err)
	}

	keyMetadata, err := decryptBlob(identityPrivate, blobResult)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt blob: %w", err)
	}

	validKeys := filterKeysByAttestation(keyMetadata.Keys, opts.AttestationEnv, opts.AcceptSoftwareApproverKeys)
	rejectedCount := len(keyMetadata.Keys) - len(validKeys)
	if rejectedCount > 0 {
		syncLog.Warn("rejected %d keys with invalid attestation", rejectedCount)
	}

	var syncedKeys []SyncedKey
	for _, key := range validKeys {
		cfg.AddKey(key)
		syncedKeys = append(syncedKeys, SyncedKey{
			PublicKeyHex: key.Hex(),
			Label:        key.Label,
			Purpose:      key.Purpose,
			DeviceName:   key.DeviceName,
		})
	}

	syncLog.Debug("synced %d keys from blob (%d rejected)", len(syncedKeys), rejectedCount)
	return syncedKeys, nil
}

// decryptBlob decrypts the encrypted blob using the provided identity private key.
func decryptBlob(identityPrivateKey []byte, blobResult *client.BlobResult) (*KeyMetadataBlob, error) {
	var ourWrappedKey *client.WrappedKey
	for i := range blobResult.WrappedKeys {
		ourWrappedKey = &blobResult.WrappedKeys[i]
		break
	}

	if ourWrappedKey == nil {
		return nil, fmt.Errorf("no wrapped key found for this device")
	}

	ephemeralPublic, err := hex.DecodeString(ourWrappedKey.EphemeralPublicHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ephemeral public key: %w", err)
	}

	wrappingKey, err := crypto.DeriveWrappingKey(
		identityPrivateKey,
		ephemeralPublic,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to derive unwrapping key: %w", err)
	}

	symmetricKey, err := crypto.Decrypt(
		wrappingKey,
		ourWrappedKey.WrappedKeyNonce,
		ourWrappedKey.WrappedKey,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap symmetric key: %w", err)
	}

	plaintext, err := crypto.Decrypt(
		symmetricKey,
		blobResult.BlobNonce,
		blobResult.EncryptedBlob,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt blob: %w", err)
	}

	var metadata KeyMetadataBlob
	if err := json.Unmarshal(plaintext, &metadata); err != nil {
		return nil, fmt.Errorf("failed to parse key metadata: %w", err)
	}

	return &metadata, nil
}
