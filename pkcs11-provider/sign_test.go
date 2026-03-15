package main

import (
	"testing"

	"github.com/ackagent/cli/internal/shared/config"
)

// createTestKeysForSign creates key objects suitable for sign tests.
func createTestKeysForSign() []*keyObject {
	publicKey := make([]byte, 65)
	publicKey[0] = 0x04
	for i := 1; i < 65; i++ {
		publicKey[i] = byte(i)
	}

	return []*keyObject{
		{
			handle: 1, metadata: &config.KeyMetadata{Label: "Sign Key", PublicKey: []byte{0xaa, 0xbb}, IOSKeyID: "key-1", Algorithm: "ecdsa-sha2-nistp256"},
			publicKey: publicKey, publicKeyHexBytes: []byte{0xaa, 0xbb},
		},
	}
}

// TestSignInitInvalidSession verifies session validation.
func TestSignInitInvalidSession(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	rv := bridgeSignInit(999, ckmECDSA, 1)
	if rv != ckrSessionHandleInvalid {
		t.Fatalf("signInit(invalid session) = %s, want CKR_SESSION_HANDLE_INVALID", rvName(rv))
	}
}

// TestSignInitNilMechanism verifies CKR_ARGUMENTS_BAD for nil mechanism.
func TestSignInitNilMechanism(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	handle := testRegisterSession(ckfSerialSession, createTestKeysForSign())

	rv := bridgeSignInitNilMech(handle, 1)
	if rv != ckrArgumentsBad {
		t.Fatalf("signInit(nil mechanism) = %s, want CKR_ARGUMENTS_BAD", rvName(rv))
	}
}

// TestSignInitInvalidMechanism verifies CKR_MECHANISM_INVALID for unsupported mechanisms.
func TestSignInitInvalidMechanism(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	handle := testRegisterSession(ckfSerialSession, createTestKeysForSign())

	tests := []struct {
		name string
		mech uint64
	}{
		{"ECDH1_DERIVE (not a sign mechanism)", ckmECDH1Derive},
		{"random invalid mechanism", 0xDEADBEEF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Need to clear signCtx between sub-tests
			sess := bridgeGetSession(handle)
			sess.signCtx = nil

			rv := bridgeSignInit(handle, tt.mech, 1)
			if rv != ckrMechanismInvalid {
				t.Fatalf("signInit(%s) = %s, want CKR_MECHANISM_INVALID", tt.name, rvName(rv))
			}
		})
	}
}

// TestSignInitInvalidKey verifies CKR_KEY_HANDLE_INVALID for bad key handle.
func TestSignInitInvalidKey(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	handle := testRegisterSession(ckfSerialSession, createTestKeysForSign())

	rv := bridgeSignInit(handle, ckmECDSA, 999)
	if rv != ckrKeyHandleInvalid {
		t.Fatalf("signInit(invalid key) = %s, want CKR_KEY_HANDLE_INVALID", rvName(rv))
	}
}

// TestSignInitSuccess verifies successful signInit for both ECDSA mechanisms.
func TestSignInitSuccess(t *testing.T) {
	mechanisms := []struct {
		name string
		mech uint64
	}{
		{"CKM_ECDSA", ckmECDSA},
		{"CKM_ECDSA_SHA256", ckmECDSASHA256},
	}

	for _, tt := range mechanisms {
		t.Run(tt.name, func(t *testing.T) {
			bridgeResetGlobalState()
			bridgeInitialize()
			defer bridgeFinalize()

			handle := testRegisterSession(ckfSerialSession, createTestKeysForSign())
			sess := bridgeGetSession(handle)

			rv := bridgeSignInit(handle, tt.mech, 1)
			if rv != ckrOK {
				t.Fatalf("signInit(%s) = %s, want CKR_OK", tt.name, rvName(rv))
			}

			if bridgeIsSignCtxNil(sess) {
				t.Fatal("signCtx should not be nil after signInit")
			}
			if bridgeGetSignCtxMechanism(sess) != tt.mech {
				t.Errorf("signCtx.mechanism = 0x%x, want 0x%x", bridgeGetSignCtxMechanism(sess), tt.mech)
			}
			if bridgeGetSignCtxKeyHandle(sess) != 1 {
				t.Errorf("signCtx.keyHandle = %d, want 1", bridgeGetSignCtxKeyHandle(sess))
			}
		})
	}
}

// TestSignInitDoubleInit verifies CKR_OPERATION_ACTIVE for double signInit.
func TestSignInitDoubleInit(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	handle := testRegisterSession(ckfSerialSession, createTestKeysForSign())

	rv := bridgeSignInit(handle, ckmECDSA, 1)
	if rv != ckrOK {
		t.Fatalf("first signInit() = %s, want CKR_OK", rvName(rv))
	}

	rv = bridgeSignInit(handle, ckmECDSA, 1)
	if rv != ckrOperationActive {
		t.Fatalf("second signInit() = %s, want CKR_OPERATION_ACTIVE", rvName(rv))
	}
}

// TestSignNotInitialized verifies CKR_OPERATION_NOT_INITIALIZED for sign without signInit.
func TestSignNotInitialized(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	handle := testRegisterSession(ckfSerialSession, createTestKeysForSign())

	rv := bridgeSignNotInitialized(handle)
	if rv != ckrOperationNotInitialized {
		t.Fatalf("sign(not init) = %s, want CKR_OPERATION_NOT_INITIALIZED", rvName(rv))
	}
}

// TestSignNilSignatureLen verifies CKR_ARGUMENTS_BAD for nil signatureLen.
func TestSignNilSignatureLen(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	handle := testRegisterSession(ckfSerialSession, createTestKeysForSign())
	bridgeSignInit(handle, ckmECDSA, 1)

	rv := bridgeSignNilSignatureLen(handle)
	if rv != ckrArgumentsBad {
		t.Fatalf("sign(nil sigLen) = %s, want CKR_ARGUMENTS_BAD", rvName(rv))
	}
}

// TestSignSizeQuery verifies that passing nil signature returns the required length.
func TestSignSizeQuery(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	handle := testRegisterSession(ckfSerialSession, createTestKeysForSign())
	bridgeSignInit(handle, ckmECDSA, 1)

	rv, sigLen := bridgeSignSizeQuery(handle)
	if rv != ckrOK {
		t.Fatalf("sign(size query) = %s, want CKR_OK", rvName(rv))
	}
	if sigLen != uint64(p256SignatureLen) {
		t.Errorf("sigLen = %d, want %d", sigLen, p256SignatureLen)
	}
}

// TestSignBufferTooSmall verifies CKR_BUFFER_TOO_SMALL when output buffer is too small.
func TestSignBufferTooSmall(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	handle := testRegisterSession(ckfSerialSession, createTestKeysForSign())
	bridgeSignInit(handle, ckmECDSA, 1)

	rv, sigLen := bridgeSignBufferTooSmall(handle)
	if rv != ckrBufferTooSmall {
		t.Fatalf("sign(small buffer) = %s, want CKR_BUFFER_TOO_SMALL", rvName(rv))
	}
	if sigLen != uint64(p256SignatureLen) {
		t.Errorf("sigLen after buffer too small = %d, want %d", sigLen, p256SignatureLen)
	}
}

// TestSignECDSADataLenRange verifies CKR_DATA_LEN_RANGE for wrong-size pre-hashed data.
func TestSignECDSADataLenRange(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	handle := testRegisterSession(ckfSerialSession, createTestKeysForSign())
	bridgeSignInit(handle, ckmECDSA, 1)

	badData := make([]byte, 16) // Not 32 bytes
	rv := bridgeSignBadDataLen(handle, badData)
	if rv != ckrDataLenRange {
		t.Fatalf("sign(wrong data len) = %s, want CKR_DATA_LEN_RANGE", rvName(rv))
	}

	sess := bridgeGetSession(handle)
	if !bridgeIsSignCtxNil(sess) {
		t.Error("signCtx should be nil after CKR_DATA_LEN_RANGE error")
	}
}

// TestSignUpdateNotInitialized verifies CKR_OPERATION_NOT_INITIALIZED for signUpdate without signInit.
func TestSignUpdateNotInitialized(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	handle := testRegisterSession(ckfSerialSession, createTestKeysForSign())

	rv := bridgeSignUpdate(handle, nil)
	if rv != ckrOperationNotInitialized {
		t.Fatalf("signUpdate(not init) = %s, want CKR_OPERATION_NOT_INITIALIZED", rvName(rv))
	}
}

// TestSignUpdateAccumulatesData verifies that signUpdate accumulates data.
func TestSignUpdateAccumulatesData(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	handle := testRegisterSession(ckfSerialSession, createTestKeysForSign())
	bridgeSignInit(handle, ckmECDSASHA256, 1)

	chunk1 := []byte("hello ")
	chunk2 := []byte("world")

	rv := bridgeSignUpdate(handle, chunk1)
	if rv != ckrOK {
		t.Fatalf("signUpdate(chunk1) = %s, want CKR_OK", rvName(rv))
	}

	rv = bridgeSignUpdate(handle, chunk2)
	if rv != ckrOK {
		t.Fatalf("signUpdate(chunk2) = %s, want CKR_OK", rvName(rv))
	}

	sess := bridgeGetSession(handle)
	accumulated := string(bridgeGetSignCtxData(sess))
	if accumulated != "hello world" {
		t.Errorf("accumulated data = %q, want %q", accumulated, "hello world")
	}
}

// TestSignUpdateNilData verifies signUpdate with nil/zero-length data.
func TestSignUpdateNilData(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	handle := testRegisterSession(ckfSerialSession, createTestKeysForSign())
	bridgeSignInit(handle, ckmECDSASHA256, 1)

	rv := bridgeSignUpdate(handle, nil)
	if rv != ckrOK {
		t.Fatalf("signUpdate(nil) = %s, want CKR_OK", rvName(rv))
	}

	sess := bridgeGetSession(handle)
	if len(bridgeGetSignCtxData(sess)) != 0 {
		t.Errorf("accumulated data length = %d, want 0", len(bridgeGetSignCtxData(sess)))
	}
}

// TestSignInvalidSession verifies session validation in sign().
func TestSignInvalidSession(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	rv := bridgeSignInvalidSession()
	if rv != ckrSessionHandleInvalid {
		t.Fatalf("sign(invalid session) = %s, want CKR_SESSION_HANDLE_INVALID", rvName(rv))
	}
}

// TestSignUpdateInvalidSession verifies session validation in signUpdate().
func TestSignUpdateInvalidSession(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	rv := bridgeSignUpdateInvalidSession()
	if rv != ckrSessionHandleInvalid {
		t.Fatalf("signUpdate(invalid session) = %s, want CKR_SESSION_HANDLE_INVALID", rvName(rv))
	}
}
