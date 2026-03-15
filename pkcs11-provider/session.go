package main

/*
#include <stdint.h>

typedef unsigned long CK_ULONG;
typedef CK_ULONG CK_RV;
typedef CK_ULONG CK_SESSION_HANDLE;
typedef CK_ULONG CK_OBJECT_HANDLE;
typedef CK_ULONG CK_MECHANISM_TYPE;
typedef CK_ULONG CK_STATE;
typedef CK_ULONG CK_FLAGS;
typedef CK_ULONG CK_SLOT_ID;

// Return values
#define CKR_OK                              0x00000000
#define CKR_SLOT_ID_INVALID                 0x00000003
#define CKR_DEVICE_ERROR                    0x00000030
#define CKR_SESSION_HANDLE_INVALID          0x000000B3
#define CKR_SESSION_PARALLEL_NOT_SUPPORTED  0x000000B4
#define CKR_TOKEN_NOT_PRESENT               0x000000E0
#define CKR_USER_ALREADY_LOGGED_IN          0x00000100
#define CKR_USER_NOT_LOGGED_IN              0x00000101
#define CKR_USER_PIN_NOT_INITIALIZED        0x00000102
#define CKR_CRYPTOKI_NOT_INITIALIZED        0x00000190
#define CKR_CRYPTOKI_ALREADY_INITIALIZED    0x00000191

// Session states
#define CKS_RO_PUBLIC_SESSION               0
#define CKS_RO_USER_FUNCTIONS               1
#define CKS_RW_PUBLIC_SESSION               2
#define CKS_RW_USER_FUNCTIONS               3
#define CKS_RW_SO_FUNCTIONS                 4

// Session flags
#define CKF_RW_SESSION                      0x00000002
#define CKF_SERIAL_SESSION                  0x00000004
*/
import "C"

import (
	"encoding/hex"
	"sync"

	"github.com/ackagent/cli/crypto"
	"github.com/ackagent/cli/internal/shared/config"
)

// sessionState represents the state of a PKCS#11 session
type sessionState int

const (
	sessionPublic   sessionState = iota // Not logged in
	sessionUser                         // Logged in as user
	sessionSigning                      // In a signing operation
	sessionDeriving                     // In a key derivation operation
)

// signContext holds state for an active signing operation
type signContext struct {
	mechanism C.CK_MECHANISM_TYPE
	keyHandle C.CK_OBJECT_HANDLE
	key       *config.KeyMetadata
	data      []byte // Accumulated data for multi-part signing
}

// deriveContext holds state for an active key derivation operation
type deriveContext struct {
	mechanism     C.CK_MECHANISM_TYPE
	baseKeyHandle C.CK_OBJECT_HANDLE
	key           *config.KeyMetadata
}

// session represents a PKCS#11 session
type session struct {
	handle    C.CK_SESSION_HANDLE
	slotID    C.CK_SLOT_ID
	flags     C.CK_FLAGS
	state     sessionState
	cfg       *config.Config
	keys      []*keyObject   // Keys available in this session
	signCtx   *signContext   // Active signing context (nil if not signing)
	deriveCtx *deriveContext // Active derive context (nil if not deriving)

	// Object search state
	findActive  bool
	findResults []C.CK_OBJECT_HANDLE
	findIndex   int
}

// keyObject represents a key object in the PKCS#11 module
type keyObject struct {
	handle            C.CK_OBJECT_HANDLE
	metadata          *config.KeyMetadata
	publicKey         []byte // SEC1 uncompressed: 0x04 || X || Y
	publicKeyHexBytes []byte // Public key hex string as bytes (for CKA_ID attribute)
}

// sessionManager manages PKCS#11 sessions
type sessionManager struct {
	mu          sync.RWMutex
	sessions    map[C.CK_SESSION_HANDLE]*session
	nextHandle  C.CK_SESSION_HANDLE
	initialized bool
}

// Global session manager instance
var sessions = &sessionManager{
	sessions:    make(map[C.CK_SESSION_HANDLE]*session),
	nextHandle:  1, // Handle 0 is invalid
	initialized: false,
}

// initialize initializes the session manager
func (sm *sessionManager) initialize() C.CK_RV {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.initialized {
		return C.CKR_CRYPTOKI_ALREADY_INITIALIZED
	}

	sm.initialized = true
	logDebug("Session manager initialized")
	return C.CKR_OK
}

// finalize cleans up the session manager
func (sm *sessionManager) finalize() C.CK_RV {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if !sm.initialized {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}

	// Close all sessions
	for handle := range sm.sessions {
		delete(sm.sessions, handle)
	}

	sm.nextHandle = 1
	sm.initialized = false
	logDebug("Session manager finalized")
	return C.CKR_OK
}

// isInitialized returns whether the session manager is initialized
func (sm *sessionManager) isInitialized() bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.initialized
}

// openSession creates a new session
func (sm *sessionManager) openSession(slotID C.CK_SLOT_ID, flags C.CK_FLAGS) (C.CK_SESSION_HANDLE, C.CK_RV) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if !sm.initialized {
		return 0, C.CKR_CRYPTOKI_NOT_INITIALIZED
	}

	// Validate slot
	if slotID != 0 {
		return 0, C.CKR_SLOT_ID_INVALID
	}

	// Serial session is required per PKCS#11 spec
	if flags&C.CKF_SERIAL_SESSION == 0 {
		return 0, C.CKR_SESSION_PARALLEL_NOT_SUPPORTED
	}

	// Load config
	cfg, err := config.Load()
	if err != nil {
		logError("Failed to load config: %v", err)
		return 0, C.CKR_DEVICE_ERROR
	}

	// Check if logged in
	if !cfg.IsLoggedIn() {
		logError("Not logged in - please run 'ackagent login' first")
		return 0, C.CKR_TOKEN_NOT_PRESENT
	}

	// Create session
	handle := sm.nextHandle
	sm.nextHandle++

	sess := &session{
		handle: handle,
		slotID: slotID,
		flags:  flags,
		state:  sessionPublic,
		cfg:    cfg,
	}

	// Load keys from config
	if err := sess.loadKeys(); err != nil {
		logError("Failed to load keys: %v", err)
		return 0, C.CKR_DEVICE_ERROR
	}

	sm.sessions[handle] = sess
	logDebug("Opened session %d with %d keys", handle, len(sess.keys))

	return handle, C.CKR_OK
}

// closeSession closes a session
func (sm *sessionManager) closeSession(handle C.CK_SESSION_HANDLE) C.CK_RV {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if !sm.initialized {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}

	if _, exists := sm.sessions[handle]; !exists {
		return C.CKR_SESSION_HANDLE_INVALID
	}

	delete(sm.sessions, handle)
	logDebug("Closed session %d", handle)

	return C.CKR_OK
}

// closeAllSessions closes all sessions for a slot
func (sm *sessionManager) closeAllSessions(slotID C.CK_SLOT_ID) C.CK_RV {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if !sm.initialized {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}

	if slotID != 0 {
		return C.CKR_SLOT_ID_INVALID
	}

	count := 0
	for handle, sess := range sm.sessions {
		if sess.slotID == slotID {
			delete(sm.sessions, handle)
			count++
		}
	}

	logDebug("Closed %d sessions for slot %d", count, slotID)
	return C.CKR_OK
}

// getSession returns a session by handle
func (sm *sessionManager) getSession(handle C.CK_SESSION_HANDLE) (*session, C.CK_RV) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if !sm.initialized {
		return nil, C.CKR_CRYPTOKI_NOT_INITIALIZED
	}

	sess, exists := sm.sessions[handle]
	if !exists {
		return nil, C.CKR_SESSION_HANDLE_INVALID
	}

	return sess, C.CKR_OK
}

// loadKeys loads keys from the configuration into the session.
// This includes both enrolled keys (SSH, GPG, Age) and device signing keys.
func (s *session) loadKeys() error {
	// First, load enrolled keys from cfg.Keys()
	configKeys := s.cfg.Keys()
	s.keys = make([]*keyObject, 0, len(configKeys))

	for i := range configKeys {
		km := &configKeys[i]
		s.loadKeyFromMetadata(km)
	}

	// Then, load device signing keys from cfg.UserAccount().Devices.
	// These keys use the device auth public key as CKA_ID/signing key.
	userAccount := s.cfg.UserAccount()
	if userAccount != nil {
		for _, dev := range userAccount.Devices {
			// Skip devices without auth keys.
			if len(dev.AuthPublicKey) == 0 {
				continue
			}

			// Check if this device key is already loaded (via sync)
			devAuthHex := hex.EncodeToString(dev.AuthPublicKey)
			alreadyLoaded := false
			for _, existing := range s.keys {
				if existing.metadata.Hex() == devAuthHex {
					alreadyLoaded = true
					break
				}
			}
			if alreadyLoaded {
				continue
			}

			// Create KeyMetadata for the device auth key
			km := &config.KeyMetadata{
				IOSKeyID:   dev.ApproverId,
				ApproverId: dev.ApproverId,
				Label:      dev.DeviceName,
				PublicKey:  dev.AuthPublicKey,
				Algorithm:  "ecdsa-sha2-nistp256",
			}
			s.loadKeyFromMetadata(km)
		}
	}

	return nil
}

// loadKeyFromMetadata loads a single key from KeyMetadata into the session
func (s *session) loadKeyFromMetadata(km *config.KeyMetadata) {
	// Only P-256 ECDSA keys are supported
	if km.Algorithm != "P-256" && km.Algorithm != "p256" && km.Algorithm != "secp256r1" && km.Algorithm != "ecdsa-sha2-nistp256" && km.Algorithm != "ecdsa" {
		logDebug("Skipping key %s with unsupported algorithm: %s", km.Label, km.Algorithm)
		return
	}

	// Public key hex as bytes (for CKA_ID attribute matching)
	publicKeyHexBytes := []byte(km.Hex())

	// Config stores compressed P-256 keys (33 bytes: 0x02/0x03 || X).
	// PKCS#11 requires SEC1 uncompressed format (0x04 || X || Y, 65 bytes).
	if len(km.PublicKey) != 33 || (km.PublicKey[0] != 0x02 && km.PublicKey[0] != 0x03) {
		logWarn("Key %s has invalid public key (expected 33-byte compressed P-256): length=%d", km.Label, len(km.PublicKey))
		return
	}
	uncompressed, err := crypto.DecompressPublicKey(km.PublicKey)
	if err != nil {
		logWarn("Key %s: failed to decompress public key: %v", km.Label, err)
		return
	}
	publicKey := uncompressed

	obj := &keyObject{
		handle:            C.CK_OBJECT_HANDLE(len(s.keys) + 1), // 1-based handles
		metadata:          km,
		publicKey:         publicKey,
		publicKeyHexBytes: publicKeyHexBytes,
	}
	s.keys = append(s.keys, obj)
	logDebug("Loaded key: %s (handle=%d, publicKeyHex=%s)", km.Label, obj.handle, km.Hex())
}

// getKey returns a key by handle
func (s *session) getKey(handle C.CK_OBJECT_HANDLE) *keyObject {
	for _, k := range s.keys {
		if k.handle == handle {
			return k
		}
	}
	return nil
}

// getCKState returns the PKCS#11 state for the session
func (s *session) getCKState() C.CK_STATE {
	isRW := (s.flags & C.CKF_RW_SESSION) != 0

	switch s.state {
	case sessionPublic:
		if isRW {
			return C.CKS_RW_PUBLIC_SESSION
		}
		return C.CKS_RO_PUBLIC_SESSION
	case sessionUser, sessionSigning, sessionDeriving:
		if isRW {
			return C.CKS_RW_USER_FUNCTIONS
		}
		return C.CKS_RO_USER_FUNCTIONS
	default:
		return C.CKS_RO_PUBLIC_SESSION
	}
}

// login logs into the session (PIN is ignored, auth is via prior ackagent login)
func (s *session) login() C.CK_RV {
	if s.state != sessionPublic {
		return C.CKR_USER_ALREADY_LOGGED_IN
	}

	// Verify we're still logged in
	if !s.cfg.IsLoggedIn() {
		return C.CKR_USER_PIN_NOT_INITIALIZED
	}

	s.state = sessionUser
	logDebug("Session %d logged in", s.handle)
	return C.CKR_OK
}

// logout logs out of the session
func (s *session) logout() C.CK_RV {
	if s.state == sessionPublic {
		return C.CKR_USER_NOT_LOGGED_IN
	}

	// Cancel any active operations
	s.signCtx = nil
	s.deriveCtx = nil
	s.findActive = false
	s.findResults = nil

	s.state = sessionPublic
	logDebug("Session %d logged out", s.handle)
	return C.CKR_OK
}

// parseFingerprint converts a fingerprint string to bytes
func parseFingerprint(fp string) []byte {
	// Remove spaces and colons
	clean := ""
	for _, c := range fp {
		if c != ' ' && c != ':' {
			clean += string(c)
		}
	}

	// Parse hex
	result := make([]byte, len(clean)/2)
	for i := 0; i < len(result); i++ {
		var b byte
		_, _ = parseHexByte(clean[i*2:i*2+2], &b)
		result[i] = b
	}

	return result
}

// parseHexByte parses a 2-character hex string into a byte
func parseHexByte(s string, b *byte) (int, error) {
	var val byte
	for _, c := range s {
		val <<= 4
		switch {
		case c >= '0' && c <= '9':
			val |= byte(c - '0')
		case c >= 'a' && c <= 'f':
			val |= byte(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			val |= byte(c - 'A' + 10)
		}
	}
	*b = val
	return 2, nil
}
