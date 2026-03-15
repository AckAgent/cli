// Package crypto provides cryptographic operations for the CLI.
// This file contains BBS+ anonymous attestation verification (response-level, inside E2E encrypted blob).
package crypto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	protocol "github.com/ackagent/api/go/protocol"
)

// =============================================================================
// Anonymous BBS+ Attestation (response-level, inside encrypted blob)
// =============================================================================

// clockSkewToleranceSeconds is the maximum allowed clock skew between the CLI
// host and the credential issuer, in seconds. Credentials that expired within
// this window are still accepted to avoid false rejections caused by minor
// clock drift between systems.
const clockSkewToleranceSeconds = 60

// credentialHeader is the application-specific header for BBS+ credentials.
// Must match the issuer's header in backend/internal/credential-issuer/bbs/signer.go.
const credentialHeader = "ackagent-anonymous-attestation-v2"

// totalSignerMessages is the number of issuer-signed messages in the credential vector.
// The credential message vector is: [attestationType, deviceType, issuedAt, expiresAt]
const totalSignerMessages = 4

// disclosedIndices are the credential message indices revealed during proof presentation.
// [0]=attestationType, [1]=deviceType, [3]=expiresAt. Index [2]=issuedAt is hidden.
var disclosedIndices = []int{0, 1, 3}

var (
	// ErrAnonymousAttestationInvalid indicates the BBS+ proof verification failed.
	ErrAnonymousAttestationInvalid = errors.New("anonymous attestation proof invalid")
	// ErrAttestationExpired indicates the credential has expired.
	ErrAttestationExpired = errors.New("attestation credential expired")
	// ErrAttestationScopeMismatch indicates the pseudonym scope does not match the request ID.
	ErrAttestationScopeMismatch = errors.New("attestation pseudonym scope mismatch")
	// ErrAttestationPolicyViolation indicates the attestation type does not meet the required security policy.
	ErrAttestationPolicyViolation = errors.New("attestation policy violation: hardware attestation required")
)

// AttestationPolicy defines the minimum attestation security level required
// for anonymous attestation verification. Callers use this to enforce that
// approval responses come from hardware-backed devices when needed.
type AttestationPolicy string

const (
	// AttestationPolicyAny accepts both hardware-backed and software attestation types.
	// This is the default and preserves backward compatibility.
	AttestationPolicyAny AttestationPolicy = "any"
	// AttestationPolicyHardware rejects software-only attestation and requires
	// a hardware-backed attestation type (e.g., ios_secure_enclave, android_strongbox, android_tee).
	AttestationPolicyHardware AttestationPolicy = "hardware"
)

// AttestationSecurityType represents the unified security type across platforms.
type AttestationSecurityType string

const (
	AttestationIOSSecureEnclave AttestationSecurityType = "ios_secure_enclave"
	AttestationAndroidTEE       AttestationSecurityType = "android_tee"
	AttestationAndroidStrongBox AttestationSecurityType = "android_strongbox"
	AttestationSoftware         AttestationSecurityType = "software"
)

// IsHardwareBacked returns true if the attestation type indicates hardware-backed security.
func (t AttestationSecurityType) IsHardwareBacked() bool {
	switch t {
	case AttestationIOSSecureEnclave, AttestationAndroidTEE, AttestationAndroidStrongBox:
		return true
	default:
		return false
	}
}

// CheckAttestationPolicy validates that the given attestation type satisfies the
// required policy. Returns nil if the policy is met, or ErrAttestationPolicyViolation
// if a hardware policy is configured but the attestation type is software.
func CheckAttestationPolicy(policy AttestationPolicy, attestationType string) error {
	if policy != AttestationPolicyHardware {
		return nil
	}
	secType := AttestationSecurityType(attestationType)
	if !secType.IsHardwareBacked() {
		return fmt.Errorf("%w: got %q", ErrAttestationPolicyViolation, attestationType)
	}
	return nil
}

// AnonymousAttestation represents a BBS+ proof with pseudonym for anonymous device attestation.
// The proof demonstrates that the approver holds a valid credential from a known issuer
// without revealing device identity. The pseudonym is scope-bound to the request ID
// for replay detection without cross-request correlation.
type AnonymousAttestation struct {
	// BbsProof is the serialized BBS+ selective disclosure proof with pseudonym.
	BbsProof []byte
	// Pseudonym is the 48-byte scope-bound pseudonym (compressed G1 point).
	Pseudonym []byte
	// Scope is the scope used for pseudonym derivation (typically the request ID).
	Scope string
	// PresentationHeader is the presentation-specific binding bytes.
	PresentationHeader []byte
	// RevealedAttestationType is the disclosed attestation security type
	// (e.g., "ios_secure_enclave", "android_strongbox", "software").
	RevealedAttestationType string
	// RevealedDeviceType is the disclosed device platform type (e.g., "ios", "android").
	RevealedDeviceType string
	// RevealedExpiresAt is the disclosed credential expiry as Unix epoch seconds.
	RevealedExpiresAt int64
}

// AnonymousAttestationFromAPI converts the generated protocol type to the crypto
// package's AnonymousAttestation struct.
func AnonymousAttestationFromAPI(api *protocol.AckAgentCommonAnonymousAttestation) *AnonymousAttestation {
	if api == nil {
		return nil
	}
	proofValue, err := decodeProofValue(api.Proof.ProofValue)
	if err != nil {
		return nil
	}
	body := api.AckagentAnonymousAttestation
	revealed := body.RevealedMessages
	return &AnonymousAttestation{
		BbsProof:                proofValue,
		Pseudonym:               body.Pseudonym,
		Scope:                   body.Scope,
		PresentationHeader:      body.PresentationHeader,
		RevealedAttestationType: string(revealed.AttestationType),
		RevealedDeviceType:      string(revealed.DeviceType),
		RevealedExpiresAt:       revealed.ExpiresAt,
	}
}

// VerifyAnonymousAttestation verifies a BBS+ selective disclosure proof with pseudonym
// using the default "any" attestation policy (accepts both hardware and software).
// See VerifyAnonymousAttestationWithPolicy for policy-aware verification.
//
// Parameters:
//   - attestation: the anonymous attestation extracted from the decrypted response
//   - requestID: the signing request ID string (used as scope for pseudonym)
//   - issuerPublicKey: 96-byte BLS12-381 G2 issuer public key
func VerifyAnonymousAttestation(attestation *AnonymousAttestation, requestID string, issuerPublicKey []byte) error {
	return VerifyAnonymousAttestationWithPolicy(attestation, requestID, issuerPublicKey, AttestationPolicyAny)
}

// VerifyAnonymousAttestationWithPolicy verifies a BBS+ selective disclosure proof with pseudonym.
// It validates that:
//  1. The pseudonym scope matches the expected request ID
//  2. The credential has not expired
//  3. The attestation type meets the required security policy
//  4. The BBS+ proof is valid against the issuer's public key
//
// Parameters:
//   - attestation: the anonymous attestation extracted from the decrypted response
//   - requestID: the signing request ID string (used as scope for pseudonym)
//   - issuerPublicKey: 96-byte BLS12-381 G2 issuer public key
//   - policy: the minimum attestation security level required
func VerifyAnonymousAttestationWithPolicy(attestation *AnonymousAttestation, requestID string, issuerPublicKey []byte, policy AttestationPolicy) error {
	if attestation == nil {
		return fmt.Errorf("anonymous attestation is nil")
	}

	// 1. Check scope matches request ID
	if attestation.Scope != requestID {
		return fmt.Errorf("%w: expected %q, got %q", ErrAttestationScopeMismatch, requestID, attestation.Scope)
	}

	// 2. Check credential expiry with clock skew tolerance.
	// Allow credentials that expired up to clockSkewToleranceSeconds ago
	// to account for minor clock drift between the issuer and this host.
	now := time.Now().Unix()
	if attestation.RevealedExpiresAt < now-clockSkewToleranceSeconds {
		return fmt.Errorf("%w: expired at %d, current time %d", ErrAttestationExpired, attestation.RevealedExpiresAt, now)
	}

	// 3. Enforce attestation type policy before doing the expensive BBS+ verification.
	if err := CheckAttestationPolicy(policy, attestation.RevealedAttestationType); err != nil {
		return err
	}

	// 4. Encode revealed messages as BBS+ message byte arrays.
	// The credential message vector is [attestationType, deviceType, issuedAt, expiresAt].
	// Disclosed indices are [0, 1, 3] (attestationType=0, deviceType=1, expiresAt=3).
	// String messages use UTF-8 bytes, int64 messages use 8-byte big-endian encoding.
	attestationTypeBytes := []byte(attestation.RevealedAttestationType)
	deviceTypeBytes := []byte(attestation.RevealedDeviceType)
	expiresAtBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(expiresAtBytes, uint64(attestation.RevealedExpiresAt))

	disclosedMessages := [][]byte{
		attestationTypeBytes,
		deviceTypeBytes,
		expiresAtBytes,
	}

	// 5. Verify BBS+ proof with pseudonym via FFI
	header := []byte(credentialHeader)
	scope := []byte(attestation.Scope)

	if err := bbsVerifyProofWithPseudonym(
		issuerPublicKey,
		attestation.BbsProof,
		attestation.Pseudonym,
		header,
		attestation.PresentationHeader,
		scope,
		totalSignerMessages,
		disclosedMessages,
		disclosedIndices,
	); err != nil {
		return fmt.Errorf("%w: %v", ErrAnonymousAttestationInvalid, err)
	}

	return nil
}
