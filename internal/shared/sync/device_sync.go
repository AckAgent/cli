package sync

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/ackagent/cli/crypto"
	"github.com/ackagent/cli/internal/shared/client"
	"github.com/ackagent/cli/internal/shared/config"
	"github.com/ackagent/cli/internal/shared/log"
)

var (
	// ErrSoftwareAttestationRejected is returned when a device has software attestation
	// and AcceptSoftwareApproverKeys is false.
	ErrSoftwareAttestationRejected = errors.New("software attestation rejected")
)

var syncLog = log.New("sync")

// SyncResult holds the result of a key sync operation.
type SyncResult struct {
	Devices []SyncedDevice
	Keys    []SyncedKey
}

// SyncedDevice represents a synced device with its metadata.
type SyncedDevice struct {
	DeviceName       string
	ApproverId       string
	AuthPublicKeyHex string
	IsAttested       bool
	AttestationType  crypto.AttestationSecurityType
	VerificationErr  error
}

// SyncedKey represents a synced signing key from the blob.
type SyncedKey struct {
	PublicKeyHex string
	Label        string
	Purpose      config.KeyPurpose
	DeviceName   string
}

// DeviceCount returns the number of synced devices.
func (r *SyncResult) DeviceCount() int {
	return len(r.Devices)
}

// KeyCount returns the number of synced keys.
func (r *SyncResult) KeyCount() int {
	return len(r.Keys)
}

// SyncOptions configures key sync behavior.
type SyncOptions struct {
	VerifyAttestation          bool
	AttestationEnv             crypto.AttestationEnvironment
	AcceptSoftwareApproverKeys bool
	BlobURL                    string
}

// SyncKeys fetches devices and signing keys from the backend.
func SyncKeys(
	ctx context.Context,
	cfg *config.Config,
	c *client.Client,
	userID, accessToken string,
	opts SyncOptions,
) (*SyncResult, error) {
	result := &SyncResult{}

	devices, err := syncDevices(ctx, cfg, c, userID, accessToken, opts)
	if err != nil {
		return nil, fmt.Errorf("sync devices failed: %w", err)
	}
	result.Devices = devices

	keys, err := syncKeyMetadata(ctx, cfg, accessToken, opts)
	if err != nil {
		if errors.Is(err, client.ErrNotFound) {
			syncLog.Debug("no blob found - user may not have enrolled keys yet")
		} else {
			syncLog.Warn("failed to sync key metadata: %v", err)
		}
	} else {
		result.Keys = keys
	}

	return result, nil
}

// syncDevices fetches devices from the login service and updates config.
func syncDevices(
	ctx context.Context,
	cfg *config.Config,
	c *client.Client,
	userID, accessToken string,
	opts SyncOptions,
) ([]SyncedDevice, error) {
	devices, err := c.ListUserDevices(ctx, userID, accessToken)
	if err != nil {
		return nil, err
	}

	var syncedDevices []SyncedDevice

	profile, err := cfg.GetActiveProfile()
	if err != nil {
		return nil, fmt.Errorf("no active profile: %w", err)
	}

	var configDevices []config.UserDevice
	for _, d := range devices {
		approverId := derefStr(d.ApproverId)
		if approverId == "" {
			continue
		}
		deviceName := derefStr(d.DeviceName)
		authPubKeyHex := derefStr(d.AuthPublicKeyHex)

		var isAttested bool
		var attestationType crypto.AttestationSecurityType
		var verificationErr error

		if opts.VerifyAttestation {
			result := verifyDeviceAttestationNew(ctx, c, approverId, accessToken, opts.AttestationEnv, opts.AcceptSoftwareApproverKeys)
			isAttested = result.Valid
			attestationType = result.AttestationType
			verificationErr = result.Err

			if result.Valid {
				syncLog.Debug("device %s attestation verified: %s", approverId, attestationType)
			} else if result.Err != nil {
				syncLog.Warn("device %s attestation verification failed: %v", approverId, result.Err)
			}
		}

		authPublicKey, _ := hex.DecodeString(authPubKeyHex)
		encPubKey, _ := hex.DecodeString(derefStr(d.EncryptionPublicKeyHex))
		var attestPubKey []byte
		if d.Attestation != nil && d.Attestation.AttestationPublicKeyHex != nil {
			attestPubKey, _ = hex.DecodeString(*d.Attestation.AttestationPublicKeyHex)
		}
		configDevices = append(configDevices, config.UserDevice{
			ApproverId:           approverId,
			AuthPublicKey:        authPublicKey,
			DeviceName:           deviceName,
			PublicKey:            encPubKey,
			AttestationPublicKey: attestPubKey,
		})

		syncedDevices = append(syncedDevices, SyncedDevice{
			DeviceName:       deviceName,
			ApproverId:       approverId,
			AuthPublicKeyHex: authPubKeyHex,
			IsAttested:       isAttested,
			AttestationType:  attestationType,
			VerificationErr:  verificationErr,
		})
	}

	if profile.UserAccount != nil {
		profile.UserAccount.Devices = configDevices
	}

	return syncedDevices, nil
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
