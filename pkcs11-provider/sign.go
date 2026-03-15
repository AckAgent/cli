package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef uint8_t CK_BYTE;
typedef CK_BYTE* CK_BYTE_PTR;
typedef unsigned long CK_ULONG;
typedef CK_ULONG* CK_ULONG_PTR;
typedef CK_ULONG CK_RV;
typedef CK_ULONG CK_SESSION_HANDLE;
typedef CK_ULONG CK_OBJECT_HANDLE;
typedef CK_ULONG CK_MECHANISM_TYPE;
typedef void* CK_VOID_PTR;

// Return values
#define CKR_OK                              0x00000000
#define CKR_ARGUMENTS_BAD                   0x00000007
#define CKR_DATA_INVALID                    0x00000020
#define CKR_DATA_LEN_RANGE                  0x00000021
#define CKR_KEY_HANDLE_INVALID              0x00000060
#define CKR_KEY_TYPE_INCONSISTENT           0x00000063
#define CKR_MECHANISM_INVALID               0x00000070
#define CKR_OPERATION_ACTIVE                0x00000090
#define CKR_OPERATION_NOT_INITIALIZED       0x00000091
#define CKR_SESSION_HANDLE_INVALID          0x000000B3
#define CKR_BUFFER_TOO_SMALL                0x00000150
#define CKR_CRYPTOKI_NOT_INITIALIZED        0x00000190
#define CKR_FUNCTION_FAILED                 0x00000006
#define CKR_USER_NOT_LOGGED_IN              0x00000101

// Mechanisms
#define CKM_ECDSA                           0x00001041
#define CKM_ECDSA_SHA256                    0x00001044

// Mechanism structure
typedef struct CK_MECHANISM {
    CK_MECHANISM_TYPE mechanism;
    CK_VOID_PTR pParameter;
    CK_ULONG ulParameterLen;
} CK_MECHANISM;
typedef CK_MECHANISM* CK_MECHANISM_PTR;
*/
import "C"

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"
	"unsafe"

	"github.com/ackagent/cli/crypto"
	relayapi "github.com/ackagent/api/go/relay"
	protocol "github.com/ackagent/api/go/protocol"
	"github.com/ackagent/cli/internal/shared/client"
	"github.com/ackagent/cli/internal/shared/config"
	"github.com/ackagent/cli/internal/shared/multidevice"
	"github.com/ackagent/cli/internal/shared/transport"
	"github.com/google/uuid"
)

// signInit initializes a signing operation
func signInit(sessionHandle C.CK_SESSION_HANDLE, mechanism C.CK_MECHANISM_PTR, keyHandle C.CK_OBJECT_HANDLE) C.CK_RV {
	sess, rv := sessions.getSession(sessionHandle)
	if rv != C.CKR_OK {
		return rv
	}

	if sess.signCtx != nil {
		return C.CKR_OPERATION_ACTIVE
	}

	if mechanism == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	// Validate mechanism
	mech := mechanism.mechanism
	if mech != C.CKM_ECDSA && mech != C.CKM_ECDSA_SHA256 {
		logError("Unsupported mechanism: %s", ckmToString(mech))
		return C.CKR_MECHANISM_INVALID
	}

	// Get the key
	key := sess.getKey(keyHandle)
	if key == nil {
		return C.CKR_KEY_HANDLE_INVALID
	}

	// Create signing context
	sess.signCtx = &signContext{
		mechanism: mech,
		keyHandle: keyHandle,
		key:       key.metadata,
		data:      nil,
	}

	logDebug("SignInit: mechanism=%s key=%s", ckmToString(mech), key.metadata.Label)
	return C.CKR_OK
}

// sign performs the signing operation
func sign(sessionHandle C.CK_SESSION_HANDLE, data C.CK_BYTE_PTR, dataLen C.CK_ULONG, signature C.CK_BYTE_PTR, signatureLen C.CK_ULONG_PTR) C.CK_RV {
	sess, rv := sessions.getSession(sessionHandle)
	if rv != C.CKR_OK {
		return rv
	}

	if sess.signCtx == nil {
		return C.CKR_OPERATION_NOT_INITIALIZED
	}

	if signatureLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	// If signature is nil, just return the required length
	if signature == nil {
		*signatureLen = C.CK_ULONG(p256SignatureLen)
		return C.CKR_OK
	}

	// Check buffer size
	if *signatureLen < C.CK_ULONG(p256SignatureLen) {
		*signatureLen = C.CK_ULONG(p256SignatureLen)
		return C.CKR_BUFFER_TOO_SMALL
	}

	// Get the data to sign
	var dataBytes []byte
	if dataLen > 0 && data != nil {
		dataBytes = C.GoBytes(unsafe.Pointer(data), C.int(dataLen))
	}

	// If there's accumulated data from SignUpdate, use that
	if len(sess.signCtx.data) > 0 {
		dataBytes = append(sess.signCtx.data, dataBytes...)
	}

	// For CKM_ECDSA_SHA256, hash the data first
	var digest []byte
	if sess.signCtx.mechanism == C.CKM_ECDSA_SHA256 {
		hash := sha256.Sum256(dataBytes)
		digest = hash[:]
	} else {
		// CKM_ECDSA expects pre-hashed data (32 bytes for P-256)
		if len(dataBytes) != 32 {
			logError("CKM_ECDSA expects 32-byte pre-hashed data, got %d bytes", len(dataBytes))
			sess.signCtx = nil
			return C.CKR_DATA_LEN_RANGE
		}
		digest = dataBytes
	}

	// Perform the signing via AckAgent relay
	sig, err := performSigning(sess.cfg, sess.signCtx.key, digest, ckmToString(sess.signCtx.mechanism))
	if err != nil {
		logError("Signing failed: %v", err)
		sess.signCtx = nil
		return C.CKR_FUNCTION_FAILED
	}

	// Copy signature to output buffer
	for i := 0; i < len(sig) && i < p256SignatureLen; i++ {
		*(*C.CK_BYTE)(unsafe.Pointer(uintptr(unsafe.Pointer(signature)) + uintptr(i))) = C.CK_BYTE(sig[i])
	}
	*signatureLen = C.CK_ULONG(len(sig))

	// Clear signing context
	sess.signCtx = nil

	logDebug("Sign: success, %d bytes", len(sig))
	return C.CKR_OK
}

// signUpdate accumulates data for multi-part signing
func signUpdate(sessionHandle C.CK_SESSION_HANDLE, data C.CK_BYTE_PTR, dataLen C.CK_ULONG) C.CK_RV {
	sess, rv := sessions.getSession(sessionHandle)
	if rv != C.CKR_OK {
		return rv
	}

	if sess.signCtx == nil {
		return C.CKR_OPERATION_NOT_INITIALIZED
	}

	if dataLen > 0 && data != nil {
		sess.signCtx.data = append(sess.signCtx.data, C.GoBytes(unsafe.Pointer(data), C.int(dataLen))...)
	}

	logDebug("SignUpdate: accumulated %d bytes", len(sess.signCtx.data))
	return C.CKR_OK
}

// signFinal completes multi-part signing
func signFinal(sessionHandle C.CK_SESSION_HANDLE, signature C.CK_BYTE_PTR, signatureLen C.CK_ULONG_PTR) C.CK_RV {
	// SignFinal is equivalent to Sign with no additional data
	return sign(sessionHandle, nil, 0, signature, signatureLen)
}

// performSigning sends a signing request to iOS via the AckAgent relay
func performSigning(cfg *config.Config, key *config.KeyMetadata, digest []byte, mechanism string) ([]byte, error) {
	if !cfg.IsLoggedIn() {
		return nil, fmt.Errorf("not logged in: please run 'ackagent login' first")
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), config.DefaultSigningTimeout)
	defer cancel()

	// Get access token
	accessToken, err := cfg.GetValidAccessToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get access token: %w", err)
	}

	// Generate ephemeral keypair for forward secrecy
	ephemeral, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	// Generate request ID
	requestID := uuid.New()
	requestIDBytes, err := requestID.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to encode request ID: %w", err)
	}

	// Build display schema and source info
	display, sourceInfo := collectSigningDisplay(key, mechanism, len(digest))

	// Build payload using generated type
	payload := &protocol.CustomPayload{
		Type:       protocol.Custom,
		Display:    *display, // CustomPayload.Display is not a pointer
		RawData:    digest,
		SourceInfo: sourceInfo,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Multi-device encryption
	encrypted, err := multidevice.EncryptForDevices(cfg, payloadBytes, requestID)
	if err != nil {
		return nil, err
	}

	// Create signing request
	relayClient, err := client.NewClient(cfg.RelayURL(), cfg.DeviceID)
	if err != nil {
		return nil, err
	}
	relayClient.SetAccessToken(accessToken)

	signingPubKey := key.Hex()
	expiresIn := int32(120)
	apiReq := &relayapi.CreateSigningRequest{
		Id:                       requestID.String(),
		RequesterId:              cfg.UserAccount().RequesterID,
		SigningPublicKeyHex:      &signingPubKey,
		RequesterEphemeralKeyHex: hex.EncodeToString(ephemeral.PublicKey[:]),
		EncryptedPayload:         encrypted.EncryptedPayload,
		PayloadNonce:             encrypted.PayloadNonce,
		WrappedKeys:              &encrypted.WrappedKeys,
		ExpiresIn:                &expiresIn,
		Timestamp:                time.Now().UnixMilli(),
	}

	resp, err := relayClient.CreateSigningRequest(ctx, apiReq)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Waiting for approval on iOS device...\n")

	// Poll for response
	status, err := relayClient.PollForResponse(ctx, resp.GetID(), config.DefaultSigningTimeout, client.DefaultPollConfig())
	if err != nil {
		return nil, fmt.Errorf("waiting for response failed: %w", err)
	}

	if status.GetStatus() == "expired" {
		return nil, fmt.Errorf("signing request expired")
	}

	if status.GetStatus() != "responded" {
		return nil, fmt.Errorf("unexpected status: %s", status.GetStatus())
	}

	// Verify ephemeral public key
	ephemeralPublic := status.GetEphemeralPublic()
	if len(ephemeralPublic) != crypto.PublicKeySize {
		return nil, fmt.Errorf("missing signer ephemeral public key in response")
	}

	// Derive response key
	responseKey, err := crypto.DeriveResponseKey(
		ephemeral.PrivateKey[:],
		ephemeralPublic,
		requestIDBytes,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to derive response key: %w", err)
	}

	// Decrypt response (request ID as AAD binds response to this request)
	decrypted, err := crypto.Decrypt(responseKey, status.GetResponseNonce(), status.GetEncryptedResponse(), requestIDBytes)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	// Parse response using generated type
	var signResponse protocol.SignatureResponse
	if err := json.Unmarshal(decrypted, &signResponse); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Check for errors
	if signResponse.ErrorCode != nil && *signResponse.ErrorCode != 0 {
		errMsg := "unknown error"
		if signResponse.ErrorMessage != nil {
			errMsg = *signResponse.ErrorMessage
		}
		return nil, fmt.Errorf("signing rejected: %s", errMsg)
	}

	// Verify anonymous attestation (BBS+ proof with pseudonym)
	var issuerKeys []transport.IssuerKeyInfo
	if profile, profileErr := cfg.GetActiveProfile(); profileErr == nil {
		if len(profile.IssuerPublicKey) > 0 {
			issuerKeys = []transport.IssuerKeyInfo{{
				ID:        profile.IssuerPublicKeyID,
				PublicKey: profile.IssuerPublicKey,
			}}
		}
	}
	if err := transport.VerifyAttestationFromJSON(decrypted, requestID.String(), issuerKeys, transport.SkipAttestationRequested()); err != nil {
		return nil, err
	}

	// Extract signature (pointer to []byte)
	if signResponse.Signature == nil {
		return nil, fmt.Errorf("missing signature in response")
	}
	signature := *signResponse.Signature
	if len(signature) != p256SignatureLen {
		return nil, fmt.Errorf("invalid signature length: expected %d, got %d", p256SignatureLen, len(signature))
	}

	return signature, nil
}
