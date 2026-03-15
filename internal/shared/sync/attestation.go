package sync

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/ackagent/cli/crypto"
	"github.com/ackagent/cli/internal/shared/client"
	"github.com/ackagent/cli/internal/shared/config"
)

// attestationVerificationResult contains the result of verifying a device's attestation.
type attestationVerificationResult struct {
	Valid           bool
	AttestationType crypto.AttestationSecurityType
	Err             error
}

// verifyDeviceAttestationNew fetches and verifies attestation using the generated API client.
func verifyDeviceAttestationNew(
	ctx context.Context,
	c *client.Client,
	approverId, accessToken string,
	env crypto.AttestationEnvironment,
	acceptSoftware bool,
) attestationVerificationResult {
	attestationData, err := c.GetAttestation(ctx, approverId, accessToken)
	if err != nil {
		return attestationVerificationResult{
			Valid:           false,
			AttestationType: crypto.AttestationSoftware,
			Err:             err,
		}
	}

	var attestationPublicKey []byte
	if attestationData.AttestationPublicKeyHex != nil {
		attestationPublicKey, _ = hex.DecodeString(*attestationData.AttestationPublicKeyHex)
	}
	var certChain [][]byte
	if attestationData.CertificateChain != nil {
		certChain = *attestationData.CertificateChain
	}
	var encryptionPublicKey []byte
	if attestationData.EncryptionPublicKeyHex != nil {
		encryptionPublicKey, _ = hex.DecodeString(*attestationData.EncryptionPublicKeyHex)
	}
	var responseAssertion []byte
	if attestationData.ResponseAssertion != nil {
		responseAssertion = *attestationData.ResponseAssertion
	}
	cryptoData := &crypto.AttestationData{
		DeviceType:           string(attestationData.DeviceType),
		AttestationType:      crypto.AttestationSecurityType(attestationData.AttestationType),
		AttestationPublicKey: attestationPublicKey,
		Timestamp:            attestationData.Timestamp,
		CertificateChain:     certChain,
		Mode:                 string(attestationData.Mode),
		ResponseAssertion:    responseAssertion,
		EncryptionPublicKey:  encryptionPublicKey,
	}

	if cryptoData.AttestationType == crypto.AttestationSoftware && !acceptSoftware {
		return attestationVerificationResult{
			Valid:           false,
			AttestationType: crypto.AttestationSoftware,
			Err:             fmt.Errorf("software attestation not accepted (use --accept-software-approver-keys to allow)"),
		}
	}

	result, err := crypto.VerifyAttestationData(cryptoData, env)
	if err != nil {
		return attestationVerificationResult{
			Valid:           false,
			AttestationType: cryptoData.AttestationType,
			Err:             err,
		}
	}

	if !result.Valid {
		errMsg := "verification failed"
		if len(result.Errors) > 0 {
			errMsg = result.Errors[0]
		}
		return attestationVerificationResult{
			Valid:           false,
			AttestationType: result.AttestationType,
			Err:             fmt.Errorf("%s", errMsg),
		}
	}

	return attestationVerificationResult{
		Valid:           true,
		AttestationType: result.AttestationType,
		Err:             nil,
	}
}

// computeKeyAttestationChallenge computes the expected challenge for a key's attestation.
// Challenge = SHA256(id || publicKey || createdAt_unix_seconds || deviceAuthPublicKeyHex)
func computeKeyAttestationChallenge(key *config.KeyMetadata) []byte {
	h := sha256.New()
	h.Write([]byte(key.IOSKeyID))
	h.Write(key.PublicKey)
	timestamp := key.CreatedAt.Unix()
	h.Write([]byte{
		byte(timestamp >> 56),
		byte(timestamp >> 48),
		byte(timestamp >> 40),
		byte(timestamp >> 32),
		byte(timestamp >> 24),
		byte(timestamp >> 16),
		byte(timestamp >> 8),
		byte(timestamp),
	})
	h.Write([]byte(key.ApproverId))
	return h.Sum(nil)
}

// KeyAttestationError represents an error during key attestation verification.
type KeyAttestationError struct {
	KeyID   string
	Message string
}

func (e *KeyAttestationError) Error() string {
	return fmt.Sprintf("key %s: %s", e.KeyID, e.Message)
}

// VerifyKeyAttestation verifies the attestation for a key received during sync.
func VerifyKeyAttestation(key *config.KeyMetadata, env crypto.AttestationEnvironment, acceptSoftware bool) error {
	if key.Attestation == nil {
		return &KeyAttestationError{
			KeyID:   key.IOSKeyID,
			Message: "missing attestation",
		}
	}

	expectedChallenge := computeKeyAttestationChallenge(key)

	if !bytes.Equal(key.Attestation.Challenge, expectedChallenge) {
		return &KeyAttestationError{
			KeyID:   key.IOSKeyID,
			Message: "challenge mismatch",
		}
	}

	if key.Attestation.AttestationType == "software" && !acceptSoftware {
		return &KeyAttestationError{
			KeyID:   key.IOSKeyID,
			Message: "software attestation not accepted",
		}
	}

	if key.Attestation.AttestationType == "software" {
		syncLog.Debug("key %s has software attestation (accepted)", key.Hex())
		return nil
	}

	verifier := crypto.NewAttestationVerifier(env)
	result, err := verifier.Verify(
		key.Attestation.PublicKey,
		key.Attestation.AttestationType,
		key.Attestation.AttestationObject,
		key.Attestation.Assertion,
		key.Attestation.Challenge,
	)
	if err != nil {
		return &KeyAttestationError{
			KeyID:   key.IOSKeyID,
			Message: fmt.Sprintf("attestation verification failed: %v", err),
		}
	}

	if !result.Valid {
		errMsg := "unknown"
		if len(result.Errors) > 0 {
			errMsg = result.Errors[0]
		}
		return &KeyAttestationError{
			KeyID:   key.IOSKeyID,
			Message: fmt.Sprintf("attestation invalid: %s", errMsg),
		}
	}

	syncLog.Debug("key %s attestation verified", key.Hex())
	return nil
}

// filterKeysByAttestation filters keys by attestation validity.
func filterKeysByAttestation(keys []config.KeyMetadata, env crypto.AttestationEnvironment, acceptSoftware bool) []config.KeyMetadata {
	var validKeys []config.KeyMetadata
	for _, key := range keys {
		k := key
		if err := VerifyKeyAttestation(&k, env, acceptSoftware); err != nil {
			syncLog.Warn("rejecting key %s (%s): %v", key.Hex(), key.IOSKeyID, err)
			continue
		}
		validKeys = append(validKeys, key)
	}
	return validKeys
}
