// Package multidevice provides helpers for multi-device encryption.
package multidevice

import (
	"encoding/hex"
	"fmt"

	"github.com/ackagent/cli/crypto"
	relayapi "github.com/ackagent/api/go/relay"
	"github.com/ackagent/cli/internal/shared/config"
	"github.com/ackagent/cli/internal/shared/log"
	"github.com/google/uuid"
)

// EncryptedPayload contains the encrypted payload and wrapped keys for multi-device encryption.
type EncryptedPayload struct {
	EncryptedPayload []byte
	PayloadNonce     []byte
	WrappedKeys      []relayapi.WrappedKey
}

// EncryptForDevices encrypts a payload for all devices in the user's account.
// It returns the encrypted payload and per-device wrapped keys.
func EncryptForDevices(cfg *config.Config, plaintext []byte, requestID uuid.UUID) (*EncryptedPayload, error) {
	requestIDBytes, err := requestID.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to encode request ID: %w", err)
	}

	// Build device keys from config
	userAccount := cfg.UserAccount()
	if userAccount == nil {
		// Debug: check what profile exists
		profile, err := cfg.GetActiveProfile()
		if profile != nil {
			log.Debug("Profile exists but userAccount is nil, err=%v", err)
		} else {
			log.Debug("No active profile found, err=%v", err)
		}
		return nil, fmt.Errorf("not logged in")
	}
	// Debug: log device info
	log.Debug("EncryptForDevices: %d devices in account", len(userAccount.Devices))
	for i, dev := range userAccount.Devices {
		log.Debug("Device %d: approverId=%s, publicKey len=%d", i, dev.ApproverId, len(dev.PublicKey))
	}
	deviceKeys := make([]crypto.DeviceKey, 0, len(userAccount.Devices))
	for _, dev := range userAccount.Devices {
		if dev.ApproverId == "" {
			continue
		}
		if len(dev.PublicKey) == crypto.PublicKeySize {
			// Hex-encode 33-byte compressed P-256 key (0x02/0x03 || X = 66 hex chars)
			// to match the format iOS/Android register with the backend
			deviceKeys = append(deviceKeys, crypto.DeviceKey{
				EncryptionPublicKeyHex: hex.EncodeToString(dev.PublicKey),
				PublicKey:              dev.PublicKey,
			})
		}
	}

	if len(deviceKeys) == 0 {
		return nil, fmt.Errorf("no valid devices found in account")
	}

	// Encrypt for multiple devices
	multiPayload, err := crypto.EncryptForMultipleDevices(plaintext, deviceKeys, requestIDBytes)
	if err != nil {
		return nil, fmt.Errorf("multi-device encryption failed: %w", err)
	}

	return &EncryptedPayload{
		EncryptedPayload: multiPayload.EncryptedPayload,
		PayloadNonce:     multiPayload.PayloadNonce,
		WrappedKeys:      multiPayload.WrappedKeys,
	}, nil
}
