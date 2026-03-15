package sync

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"
	"time"

	"github.com/ackagent/cli/crypto"
	"github.com/ackagent/cli/internal/shared/config"
)

func TestSyncResult_DeviceCount_Zero(t *testing.T) {
	r := &SyncResult{}
	if r.DeviceCount() != 0 {
		t.Errorf("DeviceCount() = %d, want 0", r.DeviceCount())
	}
}

func TestSyncResult_DeviceCount_Multiple(t *testing.T) {
	r := &SyncResult{
		Devices: []SyncedDevice{{DeviceName: "a"}, {DeviceName: "b"}},
	}
	if r.DeviceCount() != 2 {
		t.Errorf("DeviceCount() = %d, want 2", r.DeviceCount())
	}
}

func TestSyncResult_KeyCount_Zero(t *testing.T) {
	r := &SyncResult{}
	if r.KeyCount() != 0 {
		t.Errorf("KeyCount() = %d, want 0", r.KeyCount())
	}
}

func TestSyncResult_KeyCount_One(t *testing.T) {
	r := &SyncResult{Keys: []SyncedKey{{PublicKeyHex: "abc"}}}
	if r.KeyCount() != 1 {
		t.Errorf("KeyCount() = %d, want 1", r.KeyCount())
	}
}

func TestKeyAttestationError_Message(t *testing.T) {
	err := &KeyAttestationError{
		KeyID:   "key-123",
		Message: "test message",
	}
	want := "key key-123: test message"
	if err.Error() != want {
		t.Errorf("Error() = %q, want %q", err.Error(), want)
	}
}

func TestComputeKeyAttestationChallenge_ManualVerification(t *testing.T) {
	createdAt := time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC)
	key := &config.KeyMetadata{
		IOSKeyID:   "key-manual",
		PublicKey:  []byte{0xab, 0xcd, 0xef},
		CreatedAt:  createdAt,
		ApproverId: "approver-xyz",
	}

	challenge := computeKeyAttestationChallenge(key)

	// Should be SHA-256 hash (32 bytes)
	if len(challenge) != sha256.Size {
		t.Errorf("challenge length = %d, want %d", len(challenge), sha256.Size)
	}

	// Verify manually
	h := sha256.New()
	h.Write([]byte("key-manual"))
	h.Write([]byte{0xab, 0xcd, 0xef})
	ts := createdAt.Unix()
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(ts))
	h.Write(buf)
	h.Write([]byte("approver-xyz"))
	expected := h.Sum(nil)

	if string(challenge) != string(expected) {
		t.Error("challenge doesn't match manual computation")
	}
}

func TestComputeKeyAttestationChallenge_DifferentIDs(t *testing.T) {
	now := time.Now()
	k1 := &config.KeyMetadata{
		IOSKeyID: "id-1", PublicKey: []byte{0x01}, CreatedAt: now, ApproverId: "a",
	}
	k2 := &config.KeyMetadata{
		IOSKeyID: "id-2", PublicKey: []byte{0x01}, CreatedAt: now, ApproverId: "a",
	}

	c1 := computeKeyAttestationChallenge(k1)
	c2 := computeKeyAttestationChallenge(k2)

	if string(c1) == string(c2) {
		t.Error("different key IDs should produce different challenges")
	}
}

func TestVerifyKeyAttestation_MissingAttestation_ErrorType(t *testing.T) {
	key := &config.KeyMetadata{IOSKeyID: "key-test"}
	err := VerifyKeyAttestation(key, crypto.EnvDevelopment, true)
	if err == nil {
		t.Fatal("expected error")
	}
	keyErr, ok := err.(*KeyAttestationError)
	if !ok {
		t.Fatalf("expected *KeyAttestationError, got %T", err)
	}
	if keyErr.KeyID != "key-test" {
		t.Errorf("KeyID = %q, want key-test", keyErr.KeyID)
	}
}

func TestVerifyKeyAttestation_ChallengeMismatch_WithAttestation(t *testing.T) {
	key := &config.KeyMetadata{
		IOSKeyID:   "key-cm",
		PublicKey:  []byte{0x01, 0x02},
		CreatedAt:  time.Now(),
		ApproverId: "approver",
		Attestation: &config.KeyMetadataAttestation{
			Challenge:       []byte("definitely-wrong-challenge"),
			AttestationType: "software",
		},
	}

	err := VerifyKeyAttestation(key, crypto.EnvDevelopment, true)
	if err == nil {
		t.Fatal("expected error for challenge mismatch")
	}
	keyErr, ok := err.(*KeyAttestationError)
	if !ok {
		t.Fatalf("expected *KeyAttestationError, got %T", err)
	}
	if keyErr.Message != "challenge mismatch" {
		t.Errorf("Message = %q, want 'challenge mismatch'", keyErr.Message)
	}
}

func TestVerifyKeyAttestation_SoftwareAccepted_Extra(t *testing.T) {
	key := &config.KeyMetadata{
		IOSKeyID:   "key-sw",
		PublicKey:  []byte{0x01},
		CreatedAt:  time.Now(),
		ApproverId: "a",
		Attestation: &config.KeyMetadataAttestation{
			AttestationType: "software",
		},
	}
	key.Attestation.Challenge = computeKeyAttestationChallenge(key)

	err := VerifyKeyAttestation(key, crypto.EnvDevelopment, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyKeyAttestation_SoftwareRejected_Extra(t *testing.T) {
	key := &config.KeyMetadata{
		IOSKeyID:   "key-sw-rej",
		PublicKey:  []byte{0x01},
		CreatedAt:  time.Now(),
		ApproverId: "a",
		Attestation: &config.KeyMetadataAttestation{
			AttestationType: "software",
		},
	}
	key.Attestation.Challenge = computeKeyAttestationChallenge(key)

	err := VerifyKeyAttestation(key, crypto.EnvDevelopment, false)
	if err == nil {
		t.Fatal("expected error for rejected software attestation")
	}
}

func TestFilterKeysByAttestation_MixedValidity(t *testing.T) {
	now := time.Now()

	good := config.KeyMetadata{
		IOSKeyID: "good", PublicKey: []byte{0x01}, CreatedAt: now, ApproverId: "a",
		Attestation: &config.KeyMetadataAttestation{AttestationType: "software"},
	}
	good.Attestation.Challenge = computeKeyAttestationChallenge(&good)

	bad := config.KeyMetadata{
		IOSKeyID: "bad", PublicKey: []byte{0x02}, CreatedAt: now, ApproverId: "a",
		// Missing attestation
	}

	valid := filterKeysByAttestation([]config.KeyMetadata{good, bad}, crypto.EnvDevelopment, true)
	if len(valid) != 1 {
		t.Fatalf("expected 1 valid key, got %d", len(valid))
	}
	if valid[0].IOSKeyID != "good" {
		t.Errorf("expected 'good', got %q", valid[0].IOSKeyID)
	}
}

func TestFilterKeysByAttestation_EmptyList(t *testing.T) {
	valid := filterKeysByAttestation(nil, crypto.EnvDevelopment, true)
	if len(valid) != 0 {
		t.Errorf("expected 0, got %d", len(valid))
	}
}
