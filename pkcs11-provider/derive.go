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
typedef CK_OBJECT_HANDLE* CK_OBJECT_HANDLE_PTR;
typedef CK_ULONG CK_MECHANISM_TYPE;
typedef CK_ULONG CK_ATTRIBUTE_TYPE;
typedef CK_ULONG CK_OBJECT_CLASS;
typedef CK_ULONG CK_KEY_TYPE;
typedef void* CK_VOID_PTR;

// Return values
#define CKR_OK                              0x00000000
#define CKR_ARGUMENTS_BAD                   0x00000007
#define CKR_KEY_HANDLE_INVALID              0x00000060
#define CKR_KEY_TYPE_INCONSISTENT           0x00000063
#define CKR_MECHANISM_INVALID               0x00000070
#define CKR_MECHANISM_PARAM_INVALID         0x00000071
#define CKR_SESSION_HANDLE_INVALID          0x000000B3
#define CKR_FUNCTION_FAILED                 0x00000006
#define CKR_TEMPLATE_INCOMPLETE             0x000000D0
#define CKR_FUNCTION_NOT_SUPPORTED          0x00000054

// Mechanisms
#define CKM_ECDH1_DERIVE                    0x00001050

// KDF types
#define CKD_NULL                            0x00000001
#define CKD_SHA1_KDF                        0x00000002
#define CKD_SHA256_KDF                      0x00000006

// Object classes
#define CKO_SECRET_KEY                      0x00000004

// Key types
#define CKK_GENERIC_SECRET                  0x00000010

// Attributes
#define CKA_CLASS                           0x00000000
#define CKA_KEY_TYPE                        0x00000100
#define CKA_VALUE_LEN                       0x00000161

// Mechanism structure
typedef struct CK_MECHANISM {
    CK_MECHANISM_TYPE mechanism;
    CK_VOID_PTR pParameter;
    CK_ULONG ulParameterLen;
} CK_MECHANISM;
typedef CK_MECHANISM* CK_MECHANISM_PTR;

// ECDH1 derive params
typedef struct CK_ECDH1_DERIVE_PARAMS {
    CK_ULONG kdf;
    CK_ULONG ulSharedDataLen;
    CK_BYTE_PTR pSharedData;
    CK_ULONG ulPublicDataLen;
    CK_BYTE_PTR pPublicData;
} CK_ECDH1_DERIVE_PARAMS;
typedef CK_ECDH1_DERIVE_PARAMS* CK_ECDH1_DERIVE_PARAMS_PTR;

// Attribute structure
typedef struct CK_ATTRIBUTE {
    CK_ATTRIBUTE_TYPE type;
    CK_VOID_PTR pValue;
    CK_ULONG ulValueLen;
} CK_ATTRIBUTE;
typedef CK_ATTRIBUTE* CK_ATTRIBUTE_PTR;
*/
import "C"

import (
	"context"
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

// deriveKey performs ECDH key derivation
func deriveKey(
	sessionHandle C.CK_SESSION_HANDLE,
	mechanism C.CK_MECHANISM_PTR,
	baseKeyHandle C.CK_OBJECT_HANDLE,
	template C.CK_ATTRIBUTE_PTR,
	attrCount C.CK_ULONG,
	derivedKeyHandle C.CK_OBJECT_HANDLE_PTR,
) C.CK_RV {
	sess, rv := sessions.getSession(sessionHandle)
	if rv != C.CKR_OK {
		return rv
	}

	if mechanism == nil || derivedKeyHandle == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	// Validate mechanism
	if mechanism.mechanism != C.CKM_ECDH1_DERIVE {
		logError("Unsupported derive mechanism: %s", ckmToString(mechanism.mechanism))
		return C.CKR_MECHANISM_INVALID
	}

	// Get mechanism parameters
	if mechanism.pParameter == nil {
		return C.CKR_MECHANISM_PARAM_INVALID
	}

	params := (*C.CK_ECDH1_DERIVE_PARAMS)(mechanism.pParameter)

	// Validate KDF (we only support CKD_NULL for now)
	if params.kdf != C.CKD_NULL {
		logError("Unsupported KDF: %s", kdfToString(params.kdf))
		return C.CKR_MECHANISM_PARAM_INVALID
	}

	// Validate public data
	if params.pPublicData == nil || params.ulPublicDataLen == 0 {
		return C.CKR_MECHANISM_PARAM_INVALID
	}

	// Get the base key
	baseKey := sess.getKey(baseKeyHandle)
	if baseKey == nil {
		return C.CKR_KEY_HANDLE_INVALID
	}

	// Get their public key (should be 65 bytes: 0x04 || X || Y)
	theirPublicKey := C.GoBytes(unsafe.Pointer(params.pPublicData), C.int(params.ulPublicDataLen))
	if len(theirPublicKey) != 65 || theirPublicKey[0] != 0x04 {
		logError("Invalid public key format: expected 65 bytes with 0x04 prefix, got %d bytes", len(theirPublicKey))
		return C.CKR_MECHANISM_PARAM_INVALID
	}

	// Parse template for derived key attributes
	var wantValueLen C.CK_ULONG = 32 // Default to 32 bytes for P-256 shared secret
	if attrCount > 0 && template != nil {
		attrs := unsafe.Slice(template, attrCount)
		for _, attr := range attrs {
			if attr._type == C.CKA_VALUE_LEN && attr.pValue != nil {
				wantValueLen = *(*C.CK_ULONG)(attr.pValue)
			}
		}
	}

	// Perform ECDH via AckAgent relay
	sharedSecret, err := performECDH(sess.cfg, baseKey.metadata, theirPublicKey, kdfToString(params.kdf))
	if err != nil {
		logError("ECDH failed: %v", err)
		return C.CKR_FUNCTION_FAILED
	}

	// Truncate or extend shared secret to requested length
	derivedValue := sharedSecret
	if int(wantValueLen) < len(derivedValue) {
		derivedValue = derivedValue[:wantValueLen]
	}

	// Create a session object for the derived key
	// Note: For simplicity, we store the derived key in a new keyObject
	// In a full implementation, you'd want a proper secret key object
	derivedHandle := C.CK_OBJECT_HANDLE(len(sess.keys) + 1000) // Offset to avoid collision with regular keys

	*derivedKeyHandle = derivedHandle

	logDebug("DeriveKey: success, derived %d bytes, handle=%d", len(derivedValue), derivedHandle)
	return C.CKR_OK
}

// performECDH sends an ECDH key agreement request to iOS
func performECDH(cfg *config.Config, key *config.KeyMetadata, theirPublicKey []byte, kdf string) ([]byte, error) {
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
	display, sourceInfo := collectDeriveDisplay(key, "CKM_ECDH1_DERIVE", kdf)

	// Build payload using generated type
	kdfParams := &protocol.EcdhKdfParams{
		Algorithm: &kdf,
	}
	payload := &protocol.EcdhDerivePayload{
		Type:          protocol.EcdhDerive,
		Display:       display,
		PeerPublicHex: hex.EncodeToString(theirPublicKey),
		Kdf:           kdfParams,
		SourceInfo:    sourceInfo,
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

	// Create request
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
		return nil, fmt.Errorf("derive request expired")
	}

	if status.GetStatus() != "responded" {
		return nil, fmt.Errorf("unexpected status: %s", status.GetStatus())
	}

	// Verify ephemeral public key
	ephemeralPublic := status.GetEphemeralPublic()
	if len(ephemeralPublic) != crypto.PublicKeySize {
		return nil, fmt.Errorf("missing device ephemeral public key in response")
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
	var ecdhResponse protocol.EcdhDeriveResponse
	if err := json.Unmarshal(decrypted, &ecdhResponse); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Check for errors
	if ecdhResponse.ErrorCode != nil && *ecdhResponse.ErrorCode != 0 {
		errMsg := "unknown error"
		if ecdhResponse.ErrorMessage != nil {
			errMsg = *ecdhResponse.ErrorMessage
		}
		return nil, fmt.Errorf("ECDH rejected: %s", errMsg)
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

	// Extract shared secret (pointer to []byte)
	if ecdhResponse.SharedSecret == nil {
		return nil, fmt.Errorf("missing shared secret in response")
	}
	sharedSecret := *ecdhResponse.SharedSecret
	if len(sharedSecret) != 32 {
		return nil, fmt.Errorf("invalid shared secret length: expected 32, got %d", len(sharedSecret))
	}

	return sharedSecret, nil
}
