package main

import (
	"testing"

	"github.com/ackagent/cli/internal/shared/config"
)

// createTestKeysForDerive creates key objects suitable for derive tests.
func createTestKeysForDerive() []*keyObject {
	publicKey := make([]byte, 65)
	publicKey[0] = 0x04
	for i := 1; i < 65; i++ {
		publicKey[i] = byte(i)
	}

	return []*keyObject{
		{
			handle: 1, metadata: &config.KeyMetadata{Label: "Derive Key", PublicKey: []byte{0xaa, 0xbb}, IOSKeyID: "key-1", Algorithm: "ecdsa-sha2-nistp256"},
			publicKey: publicKey, publicKeyHexBytes: []byte{0xaa, 0xbb},
		},
	}
}

// makeValidPublicKey creates a 65-byte uncompressed P-256 public key (for test use).
func makeValidPublicKey() []byte {
	pk := make([]byte, 65)
	pk[0] = 0x04
	for i := 1; i < 65; i++ {
		pk[i] = byte(i + 0x40)
	}
	return pk
}

// TestDeriveKeyInvalidSession verifies session validation.
func TestDeriveKeyInvalidSession(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	rv := bridgeDeriveKeyInvalidSession()
	if rv != ckrSessionHandleInvalid {
		t.Fatalf("deriveKey(invalid session) = %s, want CKR_SESSION_HANDLE_INVALID", rvName(rv))
	}
}

// TestDeriveKeyNilMechanism verifies CKR_ARGUMENTS_BAD for nil mechanism.
func TestDeriveKeyNilMechanism(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	handle := testRegisterSession(ckfSerialSession, createTestKeysForDerive())

	rv := bridgeDeriveKeyNilMechanism(handle)
	if rv != ckrArgumentsBad {
		t.Fatalf("deriveKey(nil mechanism) = %s, want CKR_ARGUMENTS_BAD", rvName(rv))
	}
}

// TestDeriveKeyNilDerivedHandle verifies CKR_ARGUMENTS_BAD for nil derivedKeyHandle.
func TestDeriveKeyNilDerivedHandle(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	handle := testRegisterSession(ckfSerialSession, createTestKeysForDerive())

	rv := bridgeDeriveKeyNilDerivedHandle(handle)
	if rv != ckrArgumentsBad {
		t.Fatalf("deriveKey(nil derivedHandle) = %s, want CKR_ARGUMENTS_BAD", rvName(rv))
	}
}

// TestDeriveKeyInvalidMechanism verifies CKR_MECHANISM_INVALID for non-ECDH mechanism.
func TestDeriveKeyInvalidMechanism(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	handle := testRegisterSession(ckfSerialSession, createTestKeysForDerive())

	rv := bridgeDeriveKeyInvalidMechanism(handle, ckmECDSA)
	if rv != ckrMechanismInvalid {
		t.Fatalf("deriveKey(ECDSA mechanism) = %s, want CKR_MECHANISM_INVALID", rvName(rv))
	}
}

// TestDeriveKeyNilParameter verifies CKR_MECHANISM_PARAM_INVALID for nil mechanism parameter.
func TestDeriveKeyNilParameter(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	handle := testRegisterSession(ckfSerialSession, createTestKeysForDerive())

	rv := bridgeDeriveKeyNilParameter(handle)
	if rv != ckrMechanismParamInvalid {
		t.Fatalf("deriveKey(nil params) = %s, want CKR_MECHANISM_PARAM_INVALID", rvName(rv))
	}
}

// TestDeriveKeyUnsupportedKDF verifies CKR_MECHANISM_PARAM_INVALID for non-NULL KDF.
func TestDeriveKeyUnsupportedKDF(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	handle := testRegisterSession(ckfSerialSession, createTestKeysForDerive())

	pk := makeValidPublicKey()
	rv := bridgeDeriveKeyUnsupportedKDF(handle, pk, ckdSHA256KDF)
	if rv != ckrMechanismParamInvalid {
		t.Fatalf("deriveKey(SHA256 KDF) = %s, want CKR_MECHANISM_PARAM_INVALID", rvName(rv))
	}
}

// TestDeriveKeyNilPublicData verifies CKR_MECHANISM_PARAM_INVALID for nil public data.
func TestDeriveKeyNilPublicData(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	handle := testRegisterSession(ckfSerialSession, createTestKeysForDerive())

	rv := bridgeDeriveKeyNilPublicData(handle)
	if rv != ckrMechanismParamInvalid {
		t.Fatalf("deriveKey(nil public data) = %s, want CKR_MECHANISM_PARAM_INVALID", rvName(rv))
	}
}

// TestDeriveKeyInvalidPublicKeyFormat verifies CKR_MECHANISM_PARAM_INVALID for bad public key format.
func TestDeriveKeyInvalidPublicKeyFormat(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	handle := testRegisterSession(ckfSerialSession, createTestKeysForDerive())

	tests := []struct {
		name string
		pk   []byte
	}{
		{
			name: "too short (32 bytes)",
			pk:   make([]byte, 32),
		},
		{
			name: "wrong prefix (0x02)",
			pk: func() []byte {
				pk := make([]byte, 65)
				pk[0] = 0x02
				return pk
			}(),
		},
		{
			name: "too long (66 bytes)",
			pk:   make([]byte, 66),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rv := bridgeDeriveKeyInvalidPublicKey(handle, tt.pk)
			if rv != ckrMechanismParamInvalid {
				t.Fatalf("deriveKey(%s) = %s, want CKR_MECHANISM_PARAM_INVALID", tt.name, rvName(rv))
			}
		})
	}
}

// TestDeriveKeyInvalidBaseKey verifies CKR_KEY_HANDLE_INVALID for bad base key.
func TestDeriveKeyInvalidBaseKey(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	handle := testRegisterSession(ckfSerialSession, createTestKeysForDerive())

	pk := makeValidPublicKey()
	rv := bridgeDeriveKeyInvalidBaseKey(handle, pk, 999)
	if rv != ckrKeyHandleInvalid {
		t.Fatalf("deriveKey(invalid base key) = %s, want CKR_KEY_HANDLE_INVALID", rvName(rv))
	}
}
