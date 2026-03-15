package pam

import (
	"encoding/json"
	"testing"

	"github.com/ackagent/cli/crypto"
	keyauthapi "github.com/ackagent/api/go/keyauth"
	protocol "github.com/ackagent/api/go/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPushResult_Approved(t *testing.T) {
	result := &PushResult{
		Approved:         true,
		ApproverId:       "test-approver-uuid",
		AuthPublicKeyHex: "aabbccdd",
		Timestamp:        1700000000,
	}

	assert.True(t, result.Approved)
	assert.Equal(t, "test-approver-uuid", result.ApproverId)
	assert.Equal(t, "aabbccdd", result.AuthPublicKeyHex)
	assert.Equal(t, int64(1700000000), result.Timestamp)
}

func TestPushResult_Rejected(t *testing.T) {
	result := &PushResult{
		Approved: false,
	}

	assert.False(t, result.Approved)
	assert.Empty(t, result.ApproverId)
	assert.Empty(t, result.AuthPublicKeyHex)
	assert.Zero(t, result.Timestamp)
}

func TestProcessResponse_Approved(t *testing.T) {
	authenticator := &PushAuthenticator{
		config: &Config{
			Auth: AuthConfig{
				RequireAttestation: false,
			},
		},
		currentRequestID: "req-123",
	}

	authPublicKey := "aabbccdd"
	timestamp := int64(1700000000)
	response := &protocol.PamAuthResponse{
		Status:           protocol.PamAuthResponseStatusApproved,
		AuthPublicKeyHex: &authPublicKey,
		Timestamp:        &timestamp,
	}

	result, err := authenticator.processResponse(response, "user@example.com")
	require.NoError(t, err)
	assert.True(t, result.Approved)
	assert.Equal(t, "aabbccdd", result.AuthPublicKeyHex)
	assert.Equal(t, int64(1700000000), result.Timestamp)
}

func TestProcessResponse_Rejected(t *testing.T) {
	authenticator := &PushAuthenticator{
		config: &Config{
			Auth: AuthConfig{
				RequireAttestation: false,
			},
		},
	}

	response := &protocol.PamAuthResponse{
		Status: protocol.PamAuthResponseStatusRejected,
	}

	result, err := authenticator.processResponse(response, "user@example.com")
	require.NoError(t, err)
	assert.False(t, result.Approved)
}

func TestProcessResponse_ApprovedWithNilAuthPublicKey(t *testing.T) {
	authenticator := &PushAuthenticator{
		config: &Config{
			Auth: AuthConfig{
				RequireAttestation: false,
			},
		},
	}

	response := &protocol.PamAuthResponse{
		Status: protocol.PamAuthResponseStatusApproved,
	}

	result, err := authenticator.processResponse(response, "user@example.com")
	require.NoError(t, err)
	assert.True(t, result.Approved)
	assert.Empty(t, result.AuthPublicKeyHex)
}

func TestProcessResponse_ApprovedWithNilTimestamp(t *testing.T) {
	authenticator := &PushAuthenticator{
		config: &Config{
			Auth: AuthConfig{
				RequireAttestation: false,
			},
		},
	}

	authPublicKey := "aabb"
	response := &protocol.PamAuthResponse{
		Status:           protocol.PamAuthResponseStatusApproved,
		AuthPublicKeyHex: &authPublicKey,
	}

	result, err := authenticator.processResponse(response, "user@example.com")
	require.NoError(t, err)
	assert.True(t, result.Approved)
	assert.Zero(t, result.Timestamp)
}

func TestProcessResponse_UnexpectedStatus(t *testing.T) {
	authenticator := &PushAuthenticator{
		config: &Config{
			Auth: AuthConfig{
				RequireAttestation: false,
			},
		},
	}

	response := &protocol.PamAuthResponse{
		Status: "unknown",
	}

	_, err := authenticator.processResponse(response, "user@example.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected response status")
}

func TestGetDeviceKeys_NilCache(t *testing.T) {
	authenticator := &PushAuthenticator{
		config: &Config{},
		cache:  nil,
	}

	_, err := authenticator.getDeviceKeys("user@example.com")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNoDevicesForUser)
}

func TestGetDeviceKeys_EmptyCache(t *testing.T) {
	cache := &DeviceKeyCache{
		users: make(map[string]*CachedUser),
	}

	authenticator := &PushAuthenticator{
		config: &Config{},
		cache:  cache,
	}

	_, err := authenticator.getDeviceKeys("unknown@example.com")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNoDevicesForUser)
}

func TestGetDeviceKeys_InvalidPublicKey(t *testing.T) {
	cache := &DeviceKeyCache{
		users: make(map[string]*CachedUser),
	}
	cache.SetUserDevices("user@example.com", []keyauthapi.DeviceKeyInfo{
		{
			ApproverId:             "test-approver-uuid",
			EncryptionPublicKeyHex: "not-valid-hex!!!",
			AuthPublicKeyHex:       "aa",
		},
	})

	authenticator := &PushAuthenticator{
		config: &Config{},
		cache:  cache,
	}

	_, err := authenticator.getDeviceKeys("user@example.com")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNoDevicesForUser)
	assert.Contains(t, err.Error(), "no valid keys")
}

func TestGetDeviceKeys_WrongPublicKeySize(t *testing.T) {
	cache := &DeviceKeyCache{
		users: make(map[string]*CachedUser),
	}
	cache.SetUserDevices("user@example.com", []keyauthapi.DeviceKeyInfo{
		{
			ApproverId:             "test-approver-uuid",
			EncryptionPublicKeyHex: "010203", // 3 bytes when decoded
			AuthPublicKeyHex:       "aa",
		},
	})

	authenticator := &PushAuthenticator{
		config: &Config{},
		cache:  cache,
	}

	_, err := authenticator.getDeviceKeys("user@example.com")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNoDevicesForUser)
}

// Note: The old identified-mode attestation tests (TestVerifyAttestation_NilCache,
// TestVerifyAttestation_NoAttestationData, TestVerifyAttestation_NoAttestationKeysInCache)
// have been removed because attestation is now anonymous (BBS+ proof inside the
// encrypted response blob) rather than identified-mode metadata on the relay response.
// PAM anonymous attestation verification will be added when PamAuthResponse includes
// the BBS+ attestation field.

// TestDecryptAndProcess_Success tests the full decryption path with real crypto.
// Encrypts a PamAuthResponse using a known keypair, then verifies decryptAndProcess
// correctly decrypts and returns the expected PushResult.
func TestDecryptAndProcess_Success(t *testing.T) {
	// Generate ephemeral keypairs (requester and approver)
	requesterKP, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	approverKP, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	// Build a PamAuthResponse
	authPublicKey := "device-auth-pub-hex"
	timestamp := int64(1700000001)
	pamResp := protocol.PamAuthResponse{
		Status:           protocol.PamAuthResponseStatusApproved,
		AuthPublicKeyHex: &authPublicKey,
		Timestamp:        &timestamp,
	}
	plaintext, err := json.Marshal(pamResp)
	require.NoError(t, err)

	// Derive encryption key (approver encrypts with requester's public + its own private)
	requestID := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	responseKey, err := crypto.DeriveResponseKey(approverKP.PrivateKey[:], requesterKP.PublicKey[:], requestID)
	require.NoError(t, err)

	ciphertext, nonce, err := crypto.Encrypt(responseKey, plaintext, requestID)
	require.NoError(t, err)

	// Build the authenticator
	authenticator := &PushAuthenticator{
		config: &Config{
			Auth: AuthConfig{
				RequireAttestation: false,
			},
		},
		currentRequestIDBytes: requestID,
		ephemeralPrivate:      requesterKP.PrivateKey[:],
	}

	relayResp := &RelayResponseStatus{
		Status:               "responded",
		EncryptedResponse:    ciphertext,
		ApproverEphemeralKey: approverKP.PublicKey[:],
		ResponseNonce:        nonce,
	}

	result, err := authenticator.decryptAndProcess(relayResp, "user@example.com")
	require.NoError(t, err)
	assert.True(t, result.Approved)
	assert.Equal(t, "device-auth-pub-hex", result.AuthPublicKeyHex)
	assert.Equal(t, int64(1700000001), result.Timestamp)
}

// TestDecryptAndProcess_InvalidCiphertext tests that decryption failures propagate correctly.
func TestDecryptAndProcess_InvalidCiphertext(t *testing.T) {
	requesterKP, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	approverKP, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	authenticator := &PushAuthenticator{
		config: &Config{
			Auth: AuthConfig{
				RequireAttestation: false,
			},
		},
		currentRequestIDBytes: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		ephemeralPrivate:      requesterKP.PrivateKey[:],
	}

	relayResp := &RelayResponseStatus{
		Status:               "responded",
		EncryptedResponse:    []byte("this-is-not-valid-ciphertext-it-needs-to-be-longer-than-poly1305-tag"),
		ApproverEphemeralKey: approverKP.PublicKey[:],
		ResponseNonce:        make([]byte, 12), // Valid nonce size
	}

	_, err = authenticator.decryptAndProcess(relayResp, "user@example.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decrypt response")
}

// TestDecryptAndProcess_UsesCorrectEphemeralKey_Regression is a regression test for Bug 2:
// The ephemeral private key used for response decryption must be the dedicated keypair
// generated in SendPamRequest (not a per-device key from EncryptForMultipleDevices).
// If the wrong key is used, ECDH derivation produces a different shared secret and
// decryption fails.
func TestDecryptAndProcess_UsesCorrectEphemeralKey_Regression(t *testing.T) {
	// Generate the "correct" requester keypair (what SendPamRequest should return)
	correctKP, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	// Generate an approver keypair
	approverKP, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	// Encrypt response using the correct requester public key
	requestID := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	responseKey, err := crypto.DeriveResponseKey(approverKP.PrivateKey[:], correctKP.PublicKey[:], requestID)
	require.NoError(t, err)

	pamResp := protocol.PamAuthResponse{Status: protocol.PamAuthResponseStatusApproved}
	plaintext, err := json.Marshal(pamResp)
	require.NoError(t, err)

	ciphertext, nonce, err := crypto.Encrypt(responseKey, plaintext, requestID)
	require.NoError(t, err)

	relayResp := &RelayResponseStatus{
		Status:               "responded",
		EncryptedResponse:    ciphertext,
		ApproverEphemeralKey: approverKP.PublicKey[:],
		ResponseNonce:        nonce,
	}

	// Decryption with the CORRECT key succeeds
	authenticator := &PushAuthenticator{
		config:                &Config{Auth: AuthConfig{RequireAttestation: false}},
		currentRequestIDBytes: requestID,
		ephemeralPrivate:      correctKP.PrivateKey[:],
	}

	result, err := authenticator.decryptAndProcess(relayResp, "user@example.com")
	require.NoError(t, err, "decryption with correct ephemeral key must succeed")
	assert.True(t, result.Approved)

	// Decryption with a WRONG key fails (simulates the old bug where per-device key was discarded)
	wrongKP, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	authenticator.ephemeralPrivate = wrongKP.PrivateKey[:]
	_, err = authenticator.decryptAndProcess(relayResp, "user@example.com")
	assert.Error(t, err, "decryption with wrong ephemeral key must fail")
}

// Note: TestVerifyAttestation_UsesEncryptedResponse_Regression has been removed.
// The old identified-mode attestation (ECDSA over ciphertext) has been replaced with
// anonymous BBS+ attestation inside the encrypted blob. The regression scenario no longer
// applies since attestation is verified after decryption, not before.
