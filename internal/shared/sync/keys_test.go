package sync

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/ackagent/cli/crypto"
	"github.com/ackagent/cli/internal/shared/client"
	"github.com/ackagent/cli/internal/shared/config"

	blobapi "github.com/ackagent/api/go/blob"
)

// makeKeyMetadata creates a KeyMetadata with the given fields for testing.
func makeKeyMetadata(iosKeyID, publicKeyHex, approverId string, publicKey []byte, createdAt time.Time) config.KeyMetadata {
	return config.KeyMetadata{
		IOSKeyID:   iosKeyID,
		PublicKey:  publicKey,
		ApproverId: approverId,
		CreatedAt:  createdAt,
	}
}

// makeAttestedKey creates a KeyMetadata with a valid software attestation.
func makeAttestedKey(iosKeyID, publicKeyHex, approverId string, publicKey []byte, createdAt time.Time) config.KeyMetadata {
	key := makeKeyMetadata(iosKeyID, publicKeyHex, approverId, publicKey, createdAt)
	challenge := computeKeyAttestationChallenge(&key)
	key.Attestation = &config.KeyMetadataAttestation{
		Challenge:       challenge,
		AttestationType: "software",
	}
	return key
}

// --- computeKeyAttestationChallenge tests ---

func TestComputeKeyAttestationChallenge_Determinism(t *testing.T) {
	key := makeKeyMetadata("key-1", "aabbccdd", "approver-1", []byte("pubkey-data"), time.Unix(1700000000, 0))

	c1 := computeKeyAttestationChallenge(&key)
	c2 := computeKeyAttestationChallenge(&key)

	if !bytes.Equal(c1, c2) {
		t.Error("same KeyMetadata produced different challenges")
	}
}

func TestComputeKeyAttestationChallenge_Length(t *testing.T) {
	key := makeKeyMetadata("key-1", "aabbccdd", "approver-1", []byte("pubkey-data"), time.Unix(1700000000, 0))

	challenge := computeKeyAttestationChallenge(&key)
	if len(challenge) != sha256.Size {
		t.Errorf("challenge length = %d, want %d", len(challenge), sha256.Size)
	}
}

func TestComputeKeyAttestationChallenge_FieldSensitivity(t *testing.T) {
	baseTime := time.Unix(1700000000, 0)
	basePubKey := []byte("pubkey-data")

	base := makeKeyMetadata("key-1", "aabbccdd", "approver-1", basePubKey, baseTime)
	baseChallenge := computeKeyAttestationChallenge(&base)

	tests := []struct {
		name string
		key  config.KeyMetadata
	}{
		{
			name: "different IOSKeyID",
			key:  makeKeyMetadata("key-2", "aabbccdd", "approver-1", basePubKey, baseTime),
		},
		{
			name: "different PublicKey",
			key:  makeKeyMetadata("key-1", "aabbccdd", "approver-1", []byte("other-key"), baseTime),
		},
		{
			name: "different CreatedAt",
			key:  makeKeyMetadata("key-1", "aabbccdd", "approver-1", basePubKey, baseTime.Add(time.Second)),
		},
		{
			name: "different ApproverId",
			key:  makeKeyMetadata("key-1", "aabbccdd", "approver-2", basePubKey, baseTime),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			challenge := computeKeyAttestationChallenge(&tc.key)
			if bytes.Equal(challenge, baseChallenge) {
				t.Errorf("changing %s did not produce a different challenge", tc.name)
			}
		})
	}
}

// --- KeyAttestationError tests ---

func TestKeyAttestationError_Format(t *testing.T) {
	err := &KeyAttestationError{
		KeyID:   "test-key-123",
		Message: "something failed",
	}
	want := "key test-key-123: something failed"
	if err.Error() != want {
		t.Errorf("Error() = %q, want %q", err.Error(), want)
	}
}

func TestKeyAttestationError_ErrorInterface(t *testing.T) {
	var err error = &KeyAttestationError{KeyID: "k1", Message: "msg"}
	var kae *KeyAttestationError
	if !errors.As(err, &kae) {
		t.Error("KeyAttestationError does not implement error interface properly")
	}
	if kae.KeyID != "k1" {
		t.Errorf("KeyID = %q, want %q", kae.KeyID, "k1")
	}
}

// --- VerifyKeyAttestation tests ---

func TestVerifyKeyAttestation_NilAttestation(t *testing.T) {
	key := makeKeyMetadata("key-1", "fp", "dev-1", []byte("pub"), time.Now())

	err := VerifyKeyAttestation(&key, crypto.EnvDevelopment, true)
	if err == nil {
		t.Fatal("expected error for nil attestation")
	}

	var kae *KeyAttestationError
	if !errors.As(err, &kae) {
		t.Fatalf("expected KeyAttestationError, got %T", err)
	}
	if kae.Message != "missing attestation" {
		t.Errorf("message = %q, want %q", kae.Message, "missing attestation")
	}
	if kae.KeyID != "key-1" {
		t.Errorf("KeyID = %q, want %q", kae.KeyID, "key-1")
	}
}

func TestVerifyKeyAttestation_ChallengeMismatch(t *testing.T) {
	key := makeKeyMetadata("key-1", "fp", "dev-1", []byte("pub"), time.Now())
	key.Attestation = &config.KeyMetadataAttestation{
		Challenge:       []byte("wrong-challenge"),
		AttestationType: "software",
	}

	err := VerifyKeyAttestation(&key, crypto.EnvDevelopment, true)
	if err == nil {
		t.Fatal("expected error for challenge mismatch")
	}

	var kae *KeyAttestationError
	if !errors.As(err, &kae) {
		t.Fatalf("expected KeyAttestationError, got %T", err)
	}
	if kae.Message != "challenge mismatch" {
		t.Errorf("message = %q, want %q", kae.Message, "challenge mismatch")
	}
}

func TestVerifyKeyAttestation_SoftwareAccepted(t *testing.T) {
	key := makeAttestedKey("key-1", "fp", "dev-1", []byte("pub"), time.Now())

	err := VerifyKeyAttestation(&key, crypto.EnvDevelopment, true)
	if err != nil {
		t.Errorf("expected nil error for accepted software attestation, got: %v", err)
	}
}

func TestVerifyKeyAttestation_SoftwareRejected(t *testing.T) {
	key := makeAttestedKey("key-1", "fp", "dev-1", []byte("pub"), time.Now())

	err := VerifyKeyAttestation(&key, crypto.EnvDevelopment, false)
	if err == nil {
		t.Fatal("expected error for rejected software attestation")
	}

	var kae *KeyAttestationError
	if !errors.As(err, &kae) {
		t.Fatalf("expected KeyAttestationError, got %T", err)
	}
	if kae.Message != "software attestation not accepted" {
		t.Errorf("message = %q, want %q", kae.Message, "software attestation not accepted")
	}
}

func TestVerifyKeyAttestation_ReturnsCorrectKeyID(t *testing.T) {
	tests := []struct {
		name     string
		iosKeyID string
	}{
		{"uuid style", "550e8400-e29b-41d4-a716-446655440000"},
		{"simple id", "my-key-id"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key := makeKeyMetadata(tc.iosKeyID, "fp", "dev", []byte("pub"), time.Now())
			// nil attestation triggers error
			err := VerifyKeyAttestation(&key, crypto.EnvDevelopment, true)

			var kae *KeyAttestationError
			if !errors.As(err, &kae) {
				t.Fatalf("expected KeyAttestationError, got %T", err)
			}
			if kae.KeyID != tc.iosKeyID {
				t.Errorf("KeyID = %q, want %q", kae.KeyID, tc.iosKeyID)
			}
		})
	}
}

// --- filterKeysByAttestation tests ---

func TestFilterKeysByAttestation_NilAttestationFiltered(t *testing.T) {
	keys := []config.KeyMetadata{
		makeKeyMetadata("key-1", "fp1", "dev", []byte("pub1"), time.Now()),
		makeAttestedKey("key-2", "fp2", "dev", []byte("pub2"), time.Now()),
	}

	valid := filterKeysByAttestation(keys, crypto.EnvDevelopment, true)
	if len(valid) != 1 {
		t.Fatalf("expected 1 valid key, got %d", len(valid))
	}
	if valid[0].IOSKeyID != "key-2" {
		t.Errorf("expected key-2, got %s", valid[0].IOSKeyID)
	}
}

func TestFilterKeysByAttestation_SoftwareAccepted(t *testing.T) {
	keys := []config.KeyMetadata{
		makeAttestedKey("key-1", "fp1", "dev", []byte("pub1"), time.Now()),
		makeAttestedKey("key-2", "fp2", "dev", []byte("pub2"), time.Now()),
	}

	valid := filterKeysByAttestation(keys, crypto.EnvDevelopment, true)
	if len(valid) != 2 {
		t.Errorf("expected 2 valid keys, got %d", len(valid))
	}
}

func TestFilterKeysByAttestation_SoftwareRejected(t *testing.T) {
	keys := []config.KeyMetadata{
		makeAttestedKey("key-1", "fp1", "dev", []byte("pub1"), time.Now()),
		makeAttestedKey("key-2", "fp2", "dev", []byte("pub2"), time.Now()),
	}

	valid := filterKeysByAttestation(keys, crypto.EnvDevelopment, false)
	if len(valid) != 0 {
		t.Errorf("expected 0 valid keys when software rejected, got %d", len(valid))
	}
}

func TestFilterKeysByAttestation_EmptyInput(t *testing.T) {
	valid := filterKeysByAttestation(nil, crypto.EnvDevelopment, true)
	if len(valid) != 0 {
		t.Errorf("expected 0 keys for nil input, got %d", len(valid))
	}

	valid = filterKeysByAttestation([]config.KeyMetadata{}, crypto.EnvDevelopment, true)
	if len(valid) != 0 {
		t.Errorf("expected 0 keys for empty input, got %d", len(valid))
	}
}

// --- decryptBlob tests ---

// buildEncryptedBlob creates a real encrypted BlobResult for testing.
// It encrypts the given KeyMetadataBlob using real crypto operations,
// returning the BlobResult and the identity private key needed to decrypt it.
func buildEncryptedBlob(t *testing.T, metadata *KeyMetadataBlob) (*client.BlobResult, []byte) {
	t.Helper()

	// Generate identity key pair (the "device" key pair)
	identityKP, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate identity key pair: %v", err)
	}

	// Generate ephemeral key pair (used for wrapping)
	ephemeralKP, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate ephemeral key pair: %v", err)
	}

	// Derive wrapping key: ECDH(ephemeral_private, identity_public)
	wrappingKey, err := crypto.DeriveWrappingKey(
		ephemeralKP.PrivateKey[:],
		identityKP.PublicKey[:],
		nil, // No request ID for blob wrapping
	)
	if err != nil {
		t.Fatalf("failed to derive wrapping key: %v", err)
	}

	// Generate random symmetric key
	symmetricKey, err := crypto.GenerateRandomBytes(crypto.KeySize)
	if err != nil {
		t.Fatalf("failed to generate symmetric key: %v", err)
	}

	// Wrap the symmetric key with the wrapping key
	wrappedSymKey, wrappedKeyNonce, err := crypto.Encrypt(wrappingKey, symmetricKey, nil)
	if err != nil {
		t.Fatalf("failed to wrap symmetric key: %v", err)
	}

	// Serialize the metadata to JSON
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("failed to marshal metadata: %v", err)
	}

	// Encrypt the blob with the symmetric key
	encryptedBlob, blobNonce, err := crypto.Encrypt(symmetricKey, metadataJSON, nil)
	if err != nil {
		t.Fatalf("failed to encrypt blob: %v", err)
	}

	blobResult := &client.BlobResult{
		BlobResponse: blobapi.BlobResponse{
			EncryptedBlob: encryptedBlob,
			BlobNonce:     blobNonce,
			WrappedKeys: []blobapi.WrappedKey{
				{
					EphemeralPublicHex: hex.EncodeToString(ephemeralKP.PublicKey[:]),
					WrappedKey:         wrappedSymKey,
					WrappedKeyNonce:    wrappedKeyNonce,
				},
			},
		},
	}

	return blobResult, identityKP.PrivateKey[:]
}

func TestDecryptBlob_RoundTrip(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	original := &KeyMetadataBlob{
		Keys: []config.KeyMetadata{
			{
				IOSKeyID:  "test-key-1",
				Label:     "My Key",
				Algorithm: config.AlgorithmP256,
				Purpose:   config.KeyPurposeGPG,
				PublicKey: []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee},
				CreatedAt: now,
			},
		},
		UpdatedAt: now,
	}

	blobResult, identityPrivate := buildEncryptedBlob(t, original)

	decrypted, err := decryptBlob(identityPrivate, blobResult)
	if err != nil {
		t.Fatalf("decryptBlob failed: %v", err)
	}

	if len(decrypted.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(decrypted.Keys))
	}
	if decrypted.Keys[0].IOSKeyID != "test-key-1" {
		t.Errorf("IOSKeyID = %q, want %q", decrypted.Keys[0].IOSKeyID, "test-key-1")
	}
	if decrypted.Keys[0].Hex() != "aabbccddee" {
		t.Errorf("Hex() = %q, want %q", decrypted.Keys[0].Hex(), "aabbccddee")
	}
	if decrypted.Keys[0].Label != "My Key" {
		t.Errorf("Label = %q, want %q", decrypted.Keys[0].Label, "My Key")
	}
	if !decrypted.UpdatedAt.Equal(now) {
		t.Errorf("UpdatedAt = %v, want %v", decrypted.UpdatedAt, now)
	}
}

func TestDecryptBlob_MultipleKeys(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	original := &KeyMetadataBlob{
		Keys: []config.KeyMetadata{
			{IOSKeyID: "key-1", PublicKey: []byte{0xaa, 0xbb, 0x01}, Purpose: config.KeyPurposeSSH},
			{IOSKeyID: "key-2", PublicKey: []byte{0xaa, 0xbb, 0x02}, Purpose: config.KeyPurposeGPG},
			{IOSKeyID: "key-3", PublicKey: []byte{0xaa, 0xbb, 0x03}, Purpose: config.KeyPurposeAge},
		},
		UpdatedAt: now,
	}

	blobResult, identityPrivate := buildEncryptedBlob(t, original)

	decrypted, err := decryptBlob(identityPrivate, blobResult)
	if err != nil {
		t.Fatalf("decryptBlob failed: %v", err)
	}
	if len(decrypted.Keys) != 3 {
		t.Fatalf("expected 3 keys, got %d", len(decrypted.Keys))
	}
	for i, want := range []string{"key-1", "key-2", "key-3"} {
		if decrypted.Keys[i].IOSKeyID != want {
			t.Errorf("Keys[%d].IOSKeyID = %q, want %q", i, decrypted.Keys[i].IOSKeyID, want)
		}
	}
}

func TestDecryptBlob_WrongPrivateKey(t *testing.T) {
	original := &KeyMetadataBlob{
		Keys:      []config.KeyMetadata{{IOSKeyID: "key-1"}},
		UpdatedAt: time.Now(),
	}

	blobResult, _ := buildEncryptedBlob(t, original)

	// Generate a different identity key pair
	wrongKP, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate wrong key pair: %v", err)
	}

	_, err = decryptBlob(wrongKP.PrivateKey[:], blobResult)
	if err == nil {
		t.Fatal("expected error when using wrong private key")
	}
}

func TestDecryptBlob_CorruptedEncryptedBlob(t *testing.T) {
	original := &KeyMetadataBlob{
		Keys:      []config.KeyMetadata{{IOSKeyID: "key-1"}},
		UpdatedAt: time.Now(),
	}

	blobResult, identityPrivate := buildEncryptedBlob(t, original)

	// Corrupt the encrypted blob
	blobResult.EncryptedBlob[0] ^= 0xff
	blobResult.EncryptedBlob[len(blobResult.EncryptedBlob)-1] ^= 0xff

	_, err := decryptBlob(identityPrivate, blobResult)
	if err == nil {
		t.Fatal("expected error for corrupted blob")
	}
}

func TestDecryptBlob_CorruptedWrappedKey(t *testing.T) {
	original := &KeyMetadataBlob{
		Keys:      []config.KeyMetadata{{IOSKeyID: "key-1"}},
		UpdatedAt: time.Now(),
	}

	blobResult, identityPrivate := buildEncryptedBlob(t, original)

	// Corrupt the wrapped key
	blobResult.WrappedKeys[0].WrappedKey[0] ^= 0xff

	_, err := decryptBlob(identityPrivate, blobResult)
	if err == nil {
		t.Fatal("expected error for corrupted wrapped key")
	}
}

func TestDecryptBlob_InvalidJSONContent(t *testing.T) {
	// Build a blob that encrypts invalid JSON instead of a KeyMetadataBlob
	identityKP, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate identity key pair: %v", err)
	}
	ephemeralKP, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate ephemeral key pair: %v", err)
	}

	wrappingKey, err := crypto.DeriveWrappingKey(ephemeralKP.PrivateKey[:], identityKP.PublicKey[:], nil)
	if err != nil {
		t.Fatalf("failed to derive wrapping key: %v", err)
	}

	symmetricKey, err := crypto.GenerateRandomBytes(crypto.KeySize)
	if err != nil {
		t.Fatalf("failed to generate symmetric key: %v", err)
	}

	wrappedSymKey, wrappedKeyNonce, err := crypto.Encrypt(wrappingKey, symmetricKey, nil)
	if err != nil {
		t.Fatalf("failed to wrap symmetric key: %v", err)
	}

	// Encrypt invalid JSON
	encryptedBlob, blobNonce, err := crypto.Encrypt(symmetricKey, []byte("{invalid json!!!"), nil)
	if err != nil {
		t.Fatalf("failed to encrypt blob: %v", err)
	}

	blobResult := &client.BlobResult{
		BlobResponse: blobapi.BlobResponse{
			EncryptedBlob: encryptedBlob,
			BlobNonce:     blobNonce,
			WrappedKeys: []blobapi.WrappedKey{
				{
					EphemeralPublicHex: hex.EncodeToString(ephemeralKP.PublicKey[:]),
					WrappedKey:         wrappedSymKey,
					WrappedKeyNonce:    wrappedKeyNonce,
				},
			},
		},
	}

	_, err = decryptBlob(identityKP.PrivateKey[:], blobResult)
	if err == nil {
		t.Fatal("expected error for invalid JSON content")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("parse key metadata")) {
		t.Errorf("error should mention parsing, got: %v", err)
	}
}

func TestDecryptBlob_EmptyWrappedKeys(t *testing.T) {
	blobResult := &client.BlobResult{
		BlobResponse: blobapi.BlobResponse{
			EncryptedBlob: []byte("encrypted"),
			BlobNonce:     make([]byte, crypto.NonceSize),
			WrappedKeys:   []blobapi.WrappedKey{},
		},
	}

	identityKP, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	_, err = decryptBlob(identityKP.PrivateKey[:], blobResult)
	if err == nil {
		t.Fatal("expected error for empty wrapped keys")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("no wrapped key found")) {
		t.Errorf("expected 'no wrapped key found' error, got: %v", err)
	}
}

// --- SyncResult tests ---

func TestSyncResult_Counts(t *testing.T) {
	t.Run("empty result", func(t *testing.T) {
		r := &SyncResult{}
		if r.DeviceCount() != 0 {
			t.Errorf("DeviceCount() = %d, want 0", r.DeviceCount())
		}
		if r.KeyCount() != 0 {
			t.Errorf("KeyCount() = %d, want 0", r.KeyCount())
		}
	})

	t.Run("with data", func(t *testing.T) {
		r := &SyncResult{
			Devices: []SyncedDevice{{DeviceName: "d1"}, {DeviceName: "d2"}},
			Keys:    []SyncedKey{{PublicKeyHex: "k1"}, {PublicKeyHex: "k2"}, {PublicKeyHex: "k3"}},
		}
		if r.DeviceCount() != 2 {
			t.Errorf("DeviceCount() = %d, want 2", r.DeviceCount())
		}
		if r.KeyCount() != 3 {
			t.Errorf("KeyCount() = %d, want 3", r.KeyCount())
		}
	})
}
