package main

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/ackagent/cli/internal/shared/config"
)

// TestSessionNotInitialized verifies operations fail when not initialized.
func TestSessionNotInitialized(t *testing.T) {
	bridgeResetGlobalState()

	_, rv := bridgeOpenSession(0, ckfSerialSession)
	if rv != ckrCryptokiNotInitialized {
		t.Errorf("openSession before init = %s, want CKR_CRYPTOKI_NOT_INITIALIZED", rvName(rv))
	}

	rv = bridgeCloseSession(1)
	if rv != ckrCryptokiNotInitialized {
		t.Errorf("closeSession before init = %s, want CKR_CRYPTOKI_NOT_INITIALIZED", rvName(rv))
	}

	rv = bridgeCloseAllSessions(0)
	if rv != ckrCryptokiNotInitialized {
		t.Errorf("closeAllSessions before init = %s, want CKR_CRYPTOKI_NOT_INITIALIZED", rvName(rv))
	}

	_, rv = bridgeGetSessionRV(1)
	if rv != ckrCryptokiNotInitialized {
		t.Errorf("getSession before init = %s, want CKR_CRYPTOKI_NOT_INITIALIZED", rvName(rv))
	}
}

// TestCloseSessionInvalidHandle verifies CKR_SESSION_HANDLE_INVALID for bad handle.
func TestCloseSessionInvalidHandle(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	rv := bridgeCloseSession(999)
	if rv != ckrSessionHandleInvalid {
		t.Fatalf("closeSession(999) = %s, want CKR_SESSION_HANDLE_INVALID", rvName(rv))
	}
}

// TestGetSessionInvalidHandle verifies CKR_SESSION_HANDLE_INVALID for bad handle.
func TestGetSessionInvalidHandle(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	_, rv := bridgeGetSessionRV(999)
	if rv != ckrSessionHandleInvalid {
		t.Fatalf("getSession(999) = %s, want CKR_SESSION_HANDLE_INVALID", rvName(rv))
	}
}

// TestCloseAllSessionsInvalidSlot verifies CKR_SLOT_ID_INVALID for bad slot.
func TestCloseAllSessionsInvalidSlot(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	rv := bridgeCloseAllSessions(99)
	if rv != ckrSlotIDInvalid {
		t.Fatalf("closeAllSessions(99) = %s, want CKR_SLOT_ID_INVALID", rvName(rv))
	}
}

// TestSessionLifecycleWithTestSession tests open/close using direct test session registration.
func TestSessionLifecycleWithTestSession(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	handle := testRegisterSession(ckfSerialSession, nil)

	// Verify session exists
	sess, rv := bridgeGetSessionRV(handle)
	if rv != ckrOK {
		t.Fatalf("getSession(%d) = %s, want CKR_OK", handle, rvName(rv))
	}
	if sess.state != sessionPublic {
		t.Errorf("initial state = %d, want sessionPublic(%d)", sess.state, sessionPublic)
	}

	// Close the session
	rv = bridgeCloseSession(handle)
	if rv != ckrOK {
		t.Fatalf("closeSession(%d) = %s, want CKR_OK", handle, rvName(rv))
	}

	// Session should no longer exist
	_, rv = bridgeGetSessionRV(handle)
	if rv != ckrSessionHandleInvalid {
		t.Fatalf("getSession after close = %s, want CKR_SESSION_HANDLE_INVALID", rvName(rv))
	}
}

// TestCloseAllSessionsWithTestSessions tests closing all sessions for a slot.
func TestCloseAllSessionsWithTestSessions(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	h1 := testRegisterSession(ckfSerialSession, nil)
	h2 := testRegisterSession(ckfSerialSession|ckfRWSession, nil)

	rv := bridgeCloseAllSessions(0)
	if rv != ckrOK {
		t.Fatalf("closeAllSessions(0) = %s, want CKR_OK", rvName(rv))
	}

	_, rv = bridgeGetSessionRV(h1)
	if rv != ckrSessionHandleInvalid {
		t.Errorf("session %d still exists after closeAll", h1)
	}

	_, rv = bridgeGetSessionRV(h2)
	if rv != ckrSessionHandleInvalid {
		t.Errorf("session %d still exists after closeAll", h2)
	}
}

// TestLoginLogoutStateTransitions tests the session state machine.
func TestLoginLogoutStateTransitions(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	handle := testRegisterSession(ckfSerialSession, nil)
	sess := bridgeGetSession(handle)

	// Initial state should be public
	if sess.state != sessionPublic {
		t.Fatalf("initial state = %d, want sessionPublic(%d)", sess.state, sessionPublic)
	}

	// Login should transition to sessionUser
	rv := bridgeLogin(sess)
	if rv != ckrOK {
		t.Fatalf("login() = %s, want CKR_OK", rvName(rv))
	}
	if sess.state != sessionUser {
		t.Fatalf("state after login = %d, want sessionUser(%d)", sess.state, sessionUser)
	}

	// Double login should fail
	rv = bridgeLogin(sess)
	if rv != ckrUserAlreadyLoggedIn {
		t.Fatalf("double login() = %s, want CKR_USER_ALREADY_LOGGED_IN", rvName(rv))
	}

	// Logout should transition back to public
	rv = bridgeLogout(sess)
	if rv != ckrOK {
		t.Fatalf("logout() = %s, want CKR_OK", rvName(rv))
	}
	if sess.state != sessionPublic {
		t.Fatalf("state after logout = %d, want sessionPublic(%d)", sess.state, sessionPublic)
	}

	// Double logout should fail
	rv = bridgeLogout(sess)
	if rv != ckrUserNotLoggedIn {
		t.Fatalf("double logout() = %s, want CKR_USER_NOT_LOGGED_IN", rvName(rv))
	}
}

// TestLoginNotLoggedInConfig verifies login fails when config is not logged in.
func TestLoginNotLoggedInConfig(t *testing.T) {
	sess := &session{
		state: sessionPublic,
		cfg:   newTestConfig(false),
	}

	rv := bridgeLogin(sess)
	if rv != ckrUserPINNotInitialized {
		t.Fatalf("login(not logged in config) = %s, want CKR_USER_PIN_NOT_INITIALIZED", rvName(rv))
	}
}

// TestLogoutCancelsActiveOperations verifies that logout clears active find/sign/derive contexts.
func TestLogoutCancelsActiveOperations(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()
	defer bridgeFinalize()

	handle := testRegisterSession(ckfSerialSession, nil)
	sess := bridgeGetSession(handle)

	bridgeLogin(sess)

	// Set up active operations
	bridgeSetSignCtx(sess, ckmECDSA, 1)
	bridgeSetDeriveCtx(sess, ckmECDH1Derive, 1)
	bridgeSetFindActive(sess, true, []uint64{1, 2, 3})

	rv := bridgeLogout(sess)
	if rv != ckrOK {
		t.Fatalf("logout() = %s, want CKR_OK", rvName(rv))
	}

	if !bridgeIsSignCtxNil(sess) {
		t.Error("signCtx should be nil after logout")
	}
	if !bridgeIsDeriveCtxNil(sess) {
		t.Error("deriveCtx should be nil after logout")
	}
	if sess.findActive {
		t.Error("findActive should be false after logout")
	}
	if sess.findResults != nil {
		t.Error("findResults should be nil after logout")
	}
}

// TestGetCKStateReadOnly verifies CK state for read-only sessions.
func TestGetCKStateReadOnly(t *testing.T) {
	sess := &session{
		state: sessionPublic,
		cfg:   newTestConfig(true),
	}
	bridgeSetSessionFlags(sess, ckfSerialSession) // No CKF_RW_SESSION

	if got := bridgeGetCKState(sess); got != cksROPublicSession {
		t.Errorf("RO public getCKState() = %d, want CKS_RO_PUBLIC_SESSION(%d)", got, cksROPublicSession)
	}

	sess.state = sessionUser
	if got := bridgeGetCKState(sess); got != cksROUserFunctions {
		t.Errorf("RO user getCKState() = %d, want CKS_RO_USER_FUNCTIONS(%d)", got, cksROUserFunctions)
	}

	sess.state = sessionSigning
	if got := bridgeGetCKState(sess); got != cksROUserFunctions {
		t.Errorf("RO signing getCKState() = %d, want CKS_RO_USER_FUNCTIONS(%d)", got, cksROUserFunctions)
	}

	sess.state = sessionDeriving
	if got := bridgeGetCKState(sess); got != cksROUserFunctions {
		t.Errorf("RO deriving getCKState() = %d, want CKS_RO_USER_FUNCTIONS(%d)", got, cksROUserFunctions)
	}
}

// TestGetCKStateReadWrite verifies CK state for read-write sessions.
func TestGetCKStateReadWrite(t *testing.T) {
	sess := &session{
		state: sessionPublic,
		cfg:   newTestConfig(true),
	}
	bridgeSetSessionFlags(sess, ckfSerialSession|ckfRWSession)

	if got := bridgeGetCKState(sess); got != cksRWPublicSession {
		t.Errorf("RW public getCKState() = %d, want CKS_RW_PUBLIC_SESSION(%d)", got, cksRWPublicSession)
	}

	sess.state = sessionUser
	if got := bridgeGetCKState(sess); got != cksRWUserFunctions {
		t.Errorf("RW user getCKState() = %d, want CKS_RW_USER_FUNCTIONS(%d)", got, cksRWUserFunctions)
	}
}

// TestGetKey verifies key lookup by handle.
func TestGetKey(t *testing.T) {
	keys := []*keyObject{
		{handle: 1, metadata: &config.KeyMetadata{Label: "key1"}},
		{handle: 2, metadata: &config.KeyMetadata{Label: "key2"}},
		{handle: 3, metadata: &config.KeyMetadata{Label: "key3"}},
	}

	sess := &session{keys: keys}

	for _, k := range keys {
		found := bridgeGetKey(sess, uint64(k.handle))
		if found == nil {
			t.Errorf("getKey(%d) returned nil", k.handle)
			continue
		}
		if found.metadata.Label != k.metadata.Label {
			t.Errorf("getKey(%d).Label = %s, want %s", k.handle, found.metadata.Label, k.metadata.Label)
		}
	}

	if bridgeGetKey(sess, 999) != nil {
		t.Error("getKey(999) should return nil")
	}
}

// validCompressedP256Key generates a valid 33-byte compressed P-256 public key
// from a deterministic scalar seed. Different seeds produce different keys.
func validCompressedP256Key(t *testing.T, seed byte) []byte {
	t.Helper()
	scalar := make([]byte, 32)
	scalar[31] = seed
	if seed == 0 {
		scalar[31] = 1
	}
	priv, err := ecdh.P256().NewPrivateKey(scalar)
	if err != nil {
		t.Fatalf("failed to create P-256 key with seed %d: %v", seed, err)
	}
	uncompressed := priv.PublicKey().Bytes()
	x := new(big.Int).SetBytes(uncompressed[1:33])
	y := new(big.Int).SetBytes(uncompressed[33:65])
	return elliptic.MarshalCompressed(elliptic.P256(), x, y)
}

// TestLoadKeyFromMetadata verifies key loading with various algorithm names and public key formats.
func TestLoadKeyFromMetadata(t *testing.T) {
	tests := []struct {
		name      string
		km        *config.KeyMetadata
		wantAdded bool
	}{
		{
			name: "P-256 algorithm with valid compressed key",
			km: &config.KeyMetadata{
				Label: "test-key-1", Algorithm: "P-256",
				PublicKey: validCompressedP256Key(t, 1),
			},
			wantAdded: true,
		},
		{
			name: "p256 algorithm with 64 byte key (rejected, wrong length)",
			km: &config.KeyMetadata{
				Label: "test-key-2", Algorithm: "p256",
				PublicKey: make([]byte, 64),
			},
			wantAdded: false,
		},
		{
			name: "ecdsa-sha2-nistp256 algorithm",
			km: &config.KeyMetadata{
				Label: "test-key-3", Algorithm: "ecdsa-sha2-nistp256",
				PublicKey: validCompressedP256Key(t, 2),
			},
			wantAdded: true,
		},
		{
			name: "secp256r1 algorithm",
			km: &config.KeyMetadata{
				Label: "test-key-4", Algorithm: "secp256r1",
				PublicKey: validCompressedP256Key(t, 3),
			},
			wantAdded: true,
		},
		{
			name: "ecdsa algorithm",
			km: &config.KeyMetadata{
				Label: "test-key-5", Algorithm: "ecdsa",
				PublicKey: validCompressedP256Key(t, 4),
			},
			wantAdded: true,
		},
		{
			name: "unsupported algorithm (X25519)",
			km: &config.KeyMetadata{
				Label: "test-key-6", Algorithm: "X25519",
				PublicKey: make([]byte, 32)},
			wantAdded: false,
		},
		{
			name: "unsupported algorithm (RSA)",
			km: &config.KeyMetadata{
				Label: "test-key-7", Algorithm: "rsa-sha2-512",
				PublicKey: make([]byte, 256)},
			wantAdded: false,
		},
		{
			name: "invalid compressed prefix (0x00)",
			km: &config.KeyMetadata{
				Label: "test-key-8", Algorithm: "P-256",
				PublicKey: make([]byte, 33)},
			wantAdded: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sess := &session{keys: make([]*keyObject, 0)}
			sess.loadKeyFromMetadata(tt.km)

			if tt.wantAdded && len(sess.keys) != 1 {
				t.Errorf("expected key to be added, but keys count = %d", len(sess.keys))
			}
			if !tt.wantAdded && len(sess.keys) != 0 {
				t.Errorf("expected key to be skipped, but keys count = %d", len(sess.keys))
			}

			if tt.wantAdded && len(sess.keys) == 1 {
				pk := sess.keys[0].publicKey
				if len(pk) != 65 {
					t.Errorf("public key length = %d, want 65", len(pk))
				}
				if pk[0] != 0x04 {
					t.Errorf("public key prefix = 0x%02x, want 0x04", pk[0])
				}
				if sess.keys[0].handle != 1 {
					t.Errorf("handle = %d, want 1", sess.keys[0].handle)
				}
			}
		})
	}
}

// TestParseFingerprint verifies fingerprint parsing from various formats.
func TestParseFingerprint(t *testing.T) {
	tests := []struct {
		input string
		want  []byte
	}{
		{"aabbccdd", []byte{0xaa, 0xbb, 0xcc, 0xdd}},
		{"aa:bb:cc:dd", []byte{0xaa, 0xbb, 0xcc, 0xdd}},
		{"AA BB CC DD", []byte{0xaa, 0xbb, 0xcc, 0xdd}},
		{"", []byte{}},
		{"ff", []byte{0xff}},
	}

	for _, tt := range tests {
		got := parseFingerprint(tt.input)
		if !bytesEqual(got, tt.want) {
			t.Errorf("parseFingerprint(%q) = %x, want %x", tt.input, got, tt.want)
		}
	}
}

// TestParseHexByte verifies single hex byte parsing.
func TestParseHexByte(t *testing.T) {
	tests := []struct {
		input string
		want  byte
	}{
		{"00", 0x00}, {"ff", 0xff}, {"FF", 0xff},
		{"0a", 0x0a}, {"A0", 0xa0}, {"42", 0x42},
	}

	for _, tt := range tests {
		var b byte
		n, err := parseHexByte(tt.input, &b)
		if err != nil {
			t.Errorf("parseHexByte(%q) error = %v", tt.input, err)
			continue
		}
		if n != 2 {
			t.Errorf("parseHexByte(%q) n = %d, want 2", tt.input, n)
		}
		if b != tt.want {
			t.Errorf("parseHexByte(%q) = 0x%02x, want 0x%02x", tt.input, b, tt.want)
		}
	}
}

// TestFinalizeClosesAllSessions verifies finalize clears all sessions.
func TestFinalizeClosesAllSessions(t *testing.T) {
	bridgeResetGlobalState()
	bridgeInitialize()

	testRegisterSession(ckfSerialSession, nil)
	testRegisterSession(ckfSerialSession, nil)

	rv := bridgeFinalize()
	if rv != ckrOK {
		t.Fatalf("finalize() = %s, want CKR_OK", rvName(rv))
	}

	sessions.mu.RLock()
	count := len(sessions.sessions)
	sessions.mu.RUnlock()

	if count != 0 {
		t.Errorf("session count after finalize = %d, want 0", count)
	}
}
