package multidevice

import (
	"encoding/hex"
	"testing"

	"github.com/ackagent/cli/crypto"
	"github.com/ackagent/cli/internal/shared/config"
	"github.com/google/uuid"
)

// createTestConfig creates a config with test devices for multi-device encryption tests
func createTestConfig(devices []config.UserDevice) *config.Config {
	cfg := &config.Config{
		Version:       config.ConfigVersion,
		DeviceID:      "test-desktop",
		DeviceName:    "Test Desktop",
		ActiveProfile: config.DefaultProfileName,
		Profiles: map[string]*config.ProfileConfig{
			config.DefaultProfileName: {
				RelayURL: "http://localhost:8080",
				UserAccount: &config.UserAccount{
					UserID:      "user-123",
					RequesterID: "requester-456",
					SASVerified: true,
					Devices:     devices,
				},
			},
		},
	}
	return cfg
}

// generateTestDevice creates a test device with a valid P-256 ECDH key pair
func generateTestDevice(approverId, name string) (config.UserDevice, *crypto.KeyPair) {
	kp, _ := crypto.GenerateKeyPair()
	return config.UserDevice{
		ApproverId: approverId,
		DeviceName: name,
		PublicKey:  kp.PublicKey[:],
		IsPrimary:  false,
	}, kp
}

func TestEncryptForDevices_SingleDevice(t *testing.T) {
	device1, kp1 := generateTestDevice("approver-uuid-1", "iPhone")
	cfg := createTestConfig([]config.UserDevice{device1})
	expectedEncPubKeyHex := hex.EncodeToString(kp1.PublicKey[:])

	requestID := uuid.New()
	plaintext := []byte("test message for single device")

	result, err := EncryptForDevices(cfg, plaintext, requestID)
	if err != nil {
		t.Fatalf("EncryptForDevices failed: %v", err)
	}

	// Verify structure
	if len(result.EncryptedPayload) == 0 {
		t.Error("EncryptedPayload should not be empty")
	}
	if len(result.PayloadNonce) != 12 {
		t.Errorf("PayloadNonce should be 12 bytes, got %d", len(result.PayloadNonce))
	}
	if len(result.WrappedKeys) != 1 {
		t.Errorf("Expected 1 wrapped key, got %d", len(result.WrappedKeys))
	}

	// Verify wrapped key fields
	wrappedKey := result.WrappedKeys[0]
	if wrappedKey.EncryptionPublicKeyHex != expectedEncPubKeyHex {
		t.Errorf("Unexpected EncryptionPublicKeyHex: %s", wrappedKey.EncryptionPublicKeyHex)
	}
	ephKey, _ := hex.DecodeString(wrappedKey.RequesterEphemeralKeyHex)
	if len(ephKey) != crypto.PublicKeySize {
		t.Errorf("RequesterEphemeralKeyHex decoded should be %d bytes, got %d", crypto.PublicKeySize, len(ephKey))
	}

	// Verify the device can decrypt
	requestIDBytes, _ := requestID.MarshalBinary()
	decrypted, err := crypto.DecryptFromMultiDevice(&crypto.MultiDevicePayload{
		EncryptedPayload: result.EncryptedPayload,
		PayloadNonce:     result.PayloadNonce,
		WrappedKeys:      result.WrappedKeys,
	}, expectedEncPubKeyHex, kp1.PrivateKey[:], requestIDBytes)
	if err != nil {
		t.Fatalf("DecryptFromMultiDevice failed: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted message mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptForDevices_MultipleDevices(t *testing.T) {
	device1, kp1 := generateTestDevice("approver-uuid-1", "iPhone")
	device2, kp2 := generateTestDevice("approver-uuid-2", "iPad")
	device3, kp3 := generateTestDevice("approver-uuid-3", "Apple Watch")
	cfg := createTestConfig([]config.UserDevice{device1, device2, device3})

	requestID := uuid.New()
	plaintext := []byte("test message for multiple devices")

	result, err := EncryptForDevices(cfg, plaintext, requestID)
	if err != nil {
		t.Fatalf("EncryptForDevices failed: %v", err)
	}

	// All 3 devices should have wrapped keys
	if len(result.WrappedKeys) != 3 {
		t.Errorf("Expected 3 wrapped keys, got %d", len(result.WrappedKeys))
	}

	requestIDBytes, _ := requestID.MarshalBinary()

	// Each device should be able to decrypt
	devices := []struct {
		encPubKeyHex string
		kp           *crypto.KeyPair
	}{
		{hex.EncodeToString(kp1.PublicKey[:]), kp1},
		{hex.EncodeToString(kp2.PublicKey[:]), kp2},
		{hex.EncodeToString(kp3.PublicKey[:]), kp3},
	}

	for _, dev := range devices {
		decrypted, err := crypto.DecryptFromMultiDevice(&crypto.MultiDevicePayload{
			EncryptedPayload: result.EncryptedPayload,
			PayloadNonce:     result.PayloadNonce,
			WrappedKeys:      result.WrappedKeys,
		}, dev.encPubKeyHex, dev.kp.PrivateKey[:], requestIDBytes)
		if err != nil {
			t.Errorf("Device %s failed to decrypt: %v", dev.encPubKeyHex, err)
			continue
		}
		if string(decrypted) != string(plaintext) {
			t.Errorf("Device %s: decrypted mismatch: got %q, want %q", dev.encPubKeyHex, decrypted, plaintext)
		}
	}
}

func TestEncryptForDevices_NotLoggedIn(t *testing.T) {
	cfg := &config.Config{
		Version:       config.ConfigVersion,
		DeviceID:      "test-desktop",
		DeviceName:    "Test Desktop",
		ActiveProfile: config.DefaultProfileName,
		Profiles: map[string]*config.ProfileConfig{
			config.DefaultProfileName: {
				RelayURL:    "http://localhost:8080",
				UserAccount: nil, // Not logged in
			},
		},
	}

	_, err := EncryptForDevices(cfg, []byte("test"), uuid.New())
	if err == nil {
		t.Error("Expected error for not logged in")
	}
	if err.Error() != "not logged in" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestEncryptForDevices_NoDevices(t *testing.T) {
	cfg := createTestConfig([]config.UserDevice{}) // Empty devices

	_, err := EncryptForDevices(cfg, []byte("test"), uuid.New())
	if err == nil {
		t.Error("Expected error for no devices")
	}
	if err.Error() != "no valid devices found in account" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestEncryptForDevices_NoValidKeys(t *testing.T) {
	// Devices with missing approver ID should be skipped
	devices := []config.UserDevice{
		{
			ApproverId: "", // Empty approver ID - should be skipped
			DeviceName: "Device 1",
			PublicKey:  make([]byte, crypto.PublicKeySize),
		},
	}
	cfg := createTestConfig(devices)

	_, err := EncryptForDevices(cfg, []byte("test"), uuid.New())
	if err == nil {
		t.Error("Expected error for no valid devices")
	}
}

func TestEncryptForDevices_InvalidKeySize(t *testing.T) {
	// Devices with wrong key size should be skipped
	devices := []config.UserDevice{
		{
			ApproverId: "approver-uuid-invalid",
			DeviceName: "Device 1",
			PublicKey:  make([]byte, 16), // Wrong size - should be 65 (P-256)
		},
	}
	cfg := createTestConfig(devices)

	_, err := EncryptForDevices(cfg, []byte("test"), uuid.New())
	if err == nil {
		t.Error("Expected error when all devices have invalid keys")
	}
}

func TestEncryptForDevices_MixedValidInvalidKeys(t *testing.T) {
	// One valid device, one invalid - should encrypt for valid only
	validDevice, validKp := generateTestDevice("approver-uuid-valid", "Valid iPhone")
	invalidDevice := config.UserDevice{
		ApproverId: "approver-uuid-invalid",
		DeviceName: "Invalid Device",
		PublicKey:  make([]byte, 16), // Wrong size
	}
	cfg := createTestConfig([]config.UserDevice{validDevice, invalidDevice})

	requestID := uuid.New()
	plaintext := []byte("test message")

	result, err := EncryptForDevices(cfg, plaintext, requestID)
	if err != nil {
		t.Fatalf("EncryptForDevices should succeed with at least one valid device: %v", err)
	}

	expectedEncPubKeyHex := hex.EncodeToString(validKp.PublicKey[:])

	// Only 1 wrapped key (for valid device)
	if len(result.WrappedKeys) != 1 {
		t.Errorf("Expected 1 wrapped key, got %d", len(result.WrappedKeys))
	}
	if result.WrappedKeys[0].EncryptionPublicKeyHex != expectedEncPubKeyHex {
		t.Errorf("Wrong EncryptionPublicKeyHex in wrapped key: %s", result.WrappedKeys[0].EncryptionPublicKeyHex)
	}

	// Valid device should decrypt successfully
	requestIDBytes, _ := requestID.MarshalBinary()
	decrypted, err := crypto.DecryptFromMultiDevice(&crypto.MultiDevicePayload{
		EncryptedPayload: result.EncryptedPayload,
		PayloadNonce:     result.PayloadNonce,
		WrappedKeys:      result.WrappedKeys,
	}, expectedEncPubKeyHex, validKp.PrivateKey[:], requestIDBytes)
	if err != nil {
		t.Fatalf("Valid device failed to decrypt: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Error("Decrypted message mismatch")
	}
}

func TestEncryptForDevices_EmptyPlaintext(t *testing.T) {
	device1, kp1 := generateTestDevice("approver-uuid-1", "iPhone")
	cfg := createTestConfig([]config.UserDevice{device1})
	encPubKeyHex := hex.EncodeToString(kp1.PublicKey[:])

	requestID := uuid.New()
	plaintext := []byte{} // Empty

	result, err := EncryptForDevices(cfg, plaintext, requestID)
	if err != nil {
		t.Fatalf("EncryptForDevices failed for empty plaintext: %v", err)
	}

	// Should still produce encrypted output (ciphertext includes auth tag)
	if len(result.EncryptedPayload) == 0 {
		t.Error("EncryptedPayload should not be empty even for empty plaintext")
	}

	// Verify decryption
	requestIDBytes, _ := requestID.MarshalBinary()
	decrypted, err := crypto.DecryptFromMultiDevice(&crypto.MultiDevicePayload{
		EncryptedPayload: result.EncryptedPayload,
		PayloadNonce:     result.PayloadNonce,
		WrappedKeys:      result.WrappedKeys,
	}, encPubKeyHex, kp1.PrivateKey[:], requestIDBytes)
	if err != nil {
		t.Fatalf("DecryptFromMultiDevice failed: %v", err)
	}
	if len(decrypted) != 0 {
		t.Errorf("Expected empty decrypted message, got %q", decrypted)
	}
}

func TestEncryptForDevices_LargePlaintext(t *testing.T) {
	device1, kp1 := generateTestDevice("approver-uuid-1", "iPhone")
	cfg := createTestConfig([]config.UserDevice{device1})
	encPubKeyHex := hex.EncodeToString(kp1.PublicKey[:])

	requestID := uuid.New()
	// 1MB plaintext
	plaintext := make([]byte, 1024*1024)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	result, err := EncryptForDevices(cfg, plaintext, requestID)
	if err != nil {
		t.Fatalf("EncryptForDevices failed for large plaintext: %v", err)
	}

	// Verify decryption
	requestIDBytes, _ := requestID.MarshalBinary()
	decrypted, err := crypto.DecryptFromMultiDevice(&crypto.MultiDevicePayload{
		EncryptedPayload: result.EncryptedPayload,
		PayloadNonce:     result.PayloadNonce,
		WrappedKeys:      result.WrappedKeys,
	}, encPubKeyHex, kp1.PrivateKey[:], requestIDBytes)
	if err != nil {
		t.Fatalf("DecryptFromMultiDevice failed: %v", err)
	}
	if len(decrypted) != len(plaintext) {
		t.Errorf("Decrypted length mismatch: got %d, want %d", len(decrypted), len(plaintext))
	}
	for i := range decrypted {
		if decrypted[i] != plaintext[i] {
			t.Errorf("Decrypted content mismatch at byte %d", i)
			break
		}
	}
}

func TestEncryptForDevices_WrongKeyCannotDecrypt(t *testing.T) {
	device1, kp1 := generateTestDevice("approver-uuid-1", "iPhone")
	cfg := createTestConfig([]config.UserDevice{device1})
	encPubKeyHex := hex.EncodeToString(kp1.PublicKey[:])

	requestID := uuid.New()
	plaintext := []byte("secret message")

	result, err := EncryptForDevices(cfg, plaintext, requestID)
	if err != nil {
		t.Fatalf("EncryptForDevices failed: %v", err)
	}

	// Try to decrypt with a different key
	wrongKp, _ := crypto.GenerateKeyPair()
	requestIDBytes, _ := requestID.MarshalBinary()
	_, err = crypto.DecryptFromMultiDevice(&crypto.MultiDevicePayload{
		EncryptedPayload: result.EncryptedPayload,
		PayloadNonce:     result.PayloadNonce,
		WrappedKeys:      result.WrappedKeys,
	}, encPubKeyHex, wrongKp.PrivateKey[:], requestIDBytes)
	if err == nil {
		t.Error("Expected decryption to fail with wrong key")
	}
}

func TestEncryptForDevices_UnknownEncPubKeyCannotDecrypt(t *testing.T) {
	device1, _ := generateTestDevice("approver-uuid-1", "iPhone")
	cfg := createTestConfig([]config.UserDevice{device1})

	requestID := uuid.New()
	plaintext := []byte("secret message")

	result, err := EncryptForDevices(cfg, plaintext, requestID)
	if err != nil {
		t.Fatalf("EncryptForDevices failed: %v", err)
	}

	// Try to decrypt with unknown encryption public key hex
	unknownKp, _ := crypto.GenerateKeyPair()
	requestIDBytes, _ := requestID.MarshalBinary()
	_, err = crypto.DecryptFromMultiDevice(&crypto.MultiDevicePayload{
		EncryptedPayload: result.EncryptedPayload,
		PayloadNonce:     result.PayloadNonce,
		WrappedKeys:      result.WrappedKeys,
	}, "unknownpubkeyhex", unknownKp.PrivateKey[:], requestIDBytes)
	if err == nil {
		t.Error("Expected decryption to fail with unknown encryption public key")
	}
}

func TestEncryptForDevices_WrongRequestIDCannotDecrypt(t *testing.T) {
	device1, kp1 := generateTestDevice("approver-uuid-1", "iPhone")
	cfg := createTestConfig([]config.UserDevice{device1})
	encPubKeyHex := hex.EncodeToString(kp1.PublicKey[:])

	requestID := uuid.New()
	plaintext := []byte("secret message")

	result, err := EncryptForDevices(cfg, plaintext, requestID)
	if err != nil {
		t.Fatalf("EncryptForDevices failed: %v", err)
	}

	// Try to decrypt with different request ID
	wrongRequestID := uuid.New()
	wrongRequestIDBytes, _ := wrongRequestID.MarshalBinary()
	_, err = crypto.DecryptFromMultiDevice(&crypto.MultiDevicePayload{
		EncryptedPayload: result.EncryptedPayload,
		PayloadNonce:     result.PayloadNonce,
		WrappedKeys:      result.WrappedKeys,
	}, encPubKeyHex, kp1.PrivateKey[:], wrongRequestIDBytes)
	if err == nil {
		t.Error("Expected decryption to fail with wrong request ID")
	}
}

func TestEncryptForDevices_EachDeviceGetsUniqueWrappingKey(t *testing.T) {
	device1, _ := generateTestDevice("approver-uuid-1", "iPhone")
	device2, _ := generateTestDevice("approver-uuid-2", "iPad")
	cfg := createTestConfig([]config.UserDevice{device1, device2})

	requestID := uuid.New()
	plaintext := []byte("test message")

	result, err := EncryptForDevices(cfg, plaintext, requestID)
	if err != nil {
		t.Fatalf("EncryptForDevices failed: %v", err)
	}

	// Each device should have different ephemeral keys
	if len(result.WrappedKeys) != 2 {
		t.Fatalf("Expected 2 wrapped keys, got %d", len(result.WrappedKeys))
	}

	key1 := result.WrappedKeys[0]
	key2 := result.WrappedKeys[1]

	// Ephemeral public keys should be different
	if key1.RequesterEphemeralKeyHex == key2.RequesterEphemeralKeyHex {
		t.Error("Ephemeral public keys should be unique per device")
	}

	// Wrapped keys should be different (different wrapping keys)
	if string(key1.WrappedKey) == string(key2.WrappedKey) {
		t.Error("Wrapped keys should be different due to unique ephemeral keys")
	}

	// Nonces should be different
	if string(key1.WrappedKeyNonce) == string(key2.WrappedKeyNonce) {
		t.Error("Wrapped key nonces should be unique")
	}
}

func TestEncryptForDevices_DeterministicRequestID(t *testing.T) {
	// Same request ID should be required for decryption
	device1, kp1 := generateTestDevice("approver-uuid-1", "iPhone")
	cfg := createTestConfig([]config.UserDevice{device1})
	encPubKeyHex := hex.EncodeToString(kp1.PublicKey[:])

	requestID := uuid.MustParse("12345678-1234-1234-1234-123456789012")
	plaintext := []byte("test message")

	result, err := EncryptForDevices(cfg, plaintext, requestID)
	if err != nil {
		t.Fatalf("EncryptForDevices failed: %v", err)
	}

	// Decrypt with correct request ID
	requestIDBytes, _ := requestID.MarshalBinary()
	decrypted, err := crypto.DecryptFromMultiDevice(&crypto.MultiDevicePayload{
		EncryptedPayload: result.EncryptedPayload,
		PayloadNonce:     result.PayloadNonce,
		WrappedKeys:      result.WrappedKeys,
	}, encPubKeyHex, kp1.PrivateKey[:], requestIDBytes)
	if err != nil {
		t.Fatalf("DecryptFromMultiDevice failed: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Error("Decrypted message mismatch")
	}
}
