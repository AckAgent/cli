// Package crypto provides multi-device encryption support
// for encrypting payloads to multiple devices with per-device key wrapping.
package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"io"

	relayapi "github.com/ackagent/api/go/relay"
	"golang.org/x/crypto/hkdf"
)

const (
	// hkdfWrappingInfo is used for per-device key wrapping
	hkdfWrappingInfo = "signer-wrap-v1"
)

// DeviceKey represents a device's public key for multi-device encryption
type DeviceKey struct {
	EncryptionPublicKeyHex string // Hex-encoded P-256 ECDH public key of the device
	PublicKey              []byte // P-256 33 bytes (compressed: 0x02/0x03 || X)
}

// MultiDevicePayload represents an encrypted payload with per-device wrapped keys
type MultiDevicePayload struct {
	EncryptedPayload []byte                `json:"encryptedPayload"`
	PayloadNonce     []byte                `json:"payloadNonce"`
	WrappedKeys      []relayapi.WrappedKey `json:"wrappedKeys"`
}

// DeriveWrappingKey derives a key wrapping key from an ECDH shared secret
func DeriveWrappingKey(ourPrivate, theirPublic, requestID []byte) ([]byte, error) {
	// Compute ECDH shared secret
	sharedSecret, err := SharedSecret(ourPrivate, theirPublic)
	if err != nil {
		return nil, err
	}
	defer clear(sharedSecret) // Zero shared secret after key derivation

	// Use HKDF to derive wrapping key
	return deriveKeyWithInfo(sharedSecret, requestID, hkdfWrappingInfo)
}

// EncryptForMultipleDevices encrypts a payload for multiple devices
// using per-device key wrapping.
//
// The algorithm:
// 1. Generate a random symmetric key
// 2. Encrypt the payload with the symmetric key (ChaCha20-Poly1305)
// 3. For each device:
//   - Generate ephemeral P-256 key pair
//   - Derive wrapping key: HKDF(ECDH(ephemeral, device_pub), requestID)
//   - Wrap symmetric key with ChaCha20-Poly1305
//
// 4. Return encrypted payload + wrapped keys
func EncryptForMultipleDevices(payload []byte, devices []DeviceKey, requestID []byte) (*MultiDevicePayload, error) {
	if len(devices) == 0 {
		return nil, ErrInvalidKeySize
	}

	// Generate random symmetric key (32 bytes)
	symmetricKey, err := GenerateRandomBytes(KeySize)
	if err != nil {
		return nil, err
	}
	defer clear(symmetricKey) // Zero symmetric key when done

	// Encrypt payload with symmetric key (request ID as AAD binds ciphertext to this request)
	encryptedPayload, payloadNonce, err := Encrypt(symmetricKey, payload, requestID)
	if err != nil {
		return nil, err
	}

	// Wrap the symmetric key for each device
	wrappedKeys := make([]relayapi.WrappedKey, 0, len(devices))
	for _, device := range devices {
		if len(device.PublicKey) != PublicKeySize {
			continue // Skip invalid keys
		}

		// Generate ephemeral key pair for this device
		ephemeralKP, err := GenerateKeyPair()
		if err != nil {
			return nil, err
		}

		// Derive wrapping key
		wrappingKey, err := DeriveWrappingKey(ephemeralKP.PrivateKey[:], device.PublicKey, requestID)
		if err != nil {
			clear(ephemeralKP.PrivateKey[:]) // Zero ephemeral private key on error
			return nil, err
		}
		clear(ephemeralKP.PrivateKey[:]) // Zero ephemeral private key after use

		// Wrap the symmetric key (request ID as AAD binds wrapped key to this request)
		wrappedSymKey, wrappedKeyNonce, err := Encrypt(wrappingKey, symmetricKey, requestID)
		clear(wrappingKey) // Zero wrapping key after use
		if err != nil {
			return nil, err
		}

		wrappedKeys = append(wrappedKeys, relayapi.WrappedKey{
			EncryptionPublicKeyHex:   device.EncryptionPublicKeyHex,
			WrappedKey:               wrappedSymKey,
			WrappedKeyNonce:          wrappedKeyNonce,
			RequesterEphemeralKeyHex: hex.EncodeToString(ephemeralKP.PublicKey[:]),
		})
	}

	return &MultiDevicePayload{
		EncryptedPayload: encryptedPayload,
		PayloadNonce:     payloadNonce,
		WrappedKeys:      wrappedKeys,
	}, nil
}

// DecryptFromMultiDevice decrypts a payload using the wrapped key for our device.
// The encryptionPublicKeyHex parameter is the hex-encoded P-256 ECDH public key of our device.
func DecryptFromMultiDevice(
	payload *MultiDevicePayload,
	encryptionPublicKeyHex string,
	devicePrivateKey []byte,
	requestID []byte,
) ([]byte, error) {
	// Find our device's wrapped key
	var ourWrappedKey *relayapi.WrappedKey
	for i := range payload.WrappedKeys {
		if payload.WrappedKeys[i].EncryptionPublicKeyHex == encryptionPublicKeyHex {
			ourWrappedKey = &payload.WrappedKeys[i]
			break
		}
	}

	if ourWrappedKey == nil {
		return nil, ErrDecryptionFailed
	}

	// Decode the requester's ephemeral public key from hex
	requesterEphemeralKey, err := hex.DecodeString(ourWrappedKey.RequesterEphemeralKeyHex)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	// Derive wrapping key
	wrappingKey, err := DeriveWrappingKey(devicePrivateKey, requesterEphemeralKey, requestID)
	if err != nil {
		return nil, err
	}
	defer clear(wrappingKey) // Zero wrapping key after use

	// Unwrap symmetric key (request ID as AAD verifies key belongs to this request)
	symmetricKey, err := Decrypt(wrappingKey, ourWrappedKey.WrappedKeyNonce, ourWrappedKey.WrappedKey, requestID)
	if err != nil {
		return nil, err
	}
	defer clear(symmetricKey) // Zero symmetric key after use

	// Decrypt payload (request ID as AAD verifies payload belongs to this request)
	return Decrypt(symmetricKey, payload.PayloadNonce, payload.EncryptedPayload, requestID)
}

// deriveKeyWithInfo derives a key using HKDF with custom info string
func deriveKeyWithInfo(secret, salt []byte, info string) ([]byte, error) {
	hkdfReader := hkdf.New(sha256.New, secret, salt, []byte(info))
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, ErrKeyDeriveFailed
	}
	return key, nil
}
