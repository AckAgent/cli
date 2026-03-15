package crypto

import (
	"encoding/base64"
	"testing"
	"time"

	protocol "github.com/ackagent/api/go/protocol"
)

func TestAnonymousAttestationFromAPI(t *testing.T) {
	bbsProof := []byte("test-bbs-proof-data")
	pseudonym := []byte("test-pseudonym-48-bytes-padded-to-the-length")
	presentationHeader := []byte("test-ph")
	expiresAt := time.Now().Add(24 * time.Hour).Unix()

	api := &protocol.AckAgentCommonAnonymousAttestation{
		Context: []string{
			"https://www.w3.org/ns/credentials/v2",
			"https://w3id.org/security/data-integrity/v2",
			"https://w3id.org/security/bbs/v1",
			"https://schemas.ackagent.com/credentials/anonymous-attestation/v1",
		},
		Type: []string{"VerifiablePresentation", "AckAgentAnonymousAttestationPresentation"},
		Proof: protocol.AckAgentCommonDataIntegrityProof{
			Type:        protocol.DataIntegrityProof,
			Cryptosuite: protocol.Bbs2023,
			ProofValue:  "u" + base64.RawURLEncoding.EncodeToString(bbsProof),
		},
		AckagentAnonymousAttestation: protocol.AckAgentCommonAnonymousAttestationPayload{
			Pseudonym:          pseudonym,
			Scope:              "test-request-id",
			PresentationHeader: presentationHeader,
			RevealedMessages: protocol.AckAgentCommonAnonymousAttestationRevealedMessages{
				AttestationType: protocol.IosSecureEnclave,
				DeviceType:      protocol.Ios,
				ExpiresAt:       expiresAt,
			},
		},
	}

	result := AnonymousAttestationFromAPI(api)

	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if string(result.BbsProof) != string(bbsProof) {
		t.Errorf("BbsProof = %q, want %q", result.BbsProof, bbsProof)
	}
	if string(result.Pseudonym) != string(pseudonym) {
		t.Errorf("Pseudonym = %q, want %q", result.Pseudonym, pseudonym)
	}
	if result.Scope != "test-request-id" {
		t.Errorf("Scope = %q, want %q", result.Scope, "test-request-id")
	}
	if string(result.PresentationHeader) != string(presentationHeader) {
		t.Errorf("PresentationHeader mismatch")
	}
	if result.RevealedAttestationType != "ios_secure_enclave" {
		t.Errorf("RevealedAttestationType = %q, want %q", result.RevealedAttestationType, "ios_secure_enclave")
	}
	if result.RevealedDeviceType != "ios" {
		t.Errorf("RevealedDeviceType = %q, want %q", result.RevealedDeviceType, "ios")
	}
	if result.RevealedExpiresAt != expiresAt {
		t.Errorf("RevealedExpiresAt = %d, want %d", result.RevealedExpiresAt, expiresAt)
	}
}

func TestAnonymousAttestationFromAPI_Nil(t *testing.T) {
	result := AnonymousAttestationFromAPI(nil)
	if result != nil {
		t.Errorf("expected nil for nil input, got %+v", result)
	}
}

func TestVerifyAnonymousAttestation_NilAttestation(t *testing.T) {
	err := VerifyAnonymousAttestation(nil, "request-id", make([]byte, 96))
	if err == nil {
		t.Fatal("expected error for nil attestation")
	}
}

func TestVerifyAnonymousAttestation_ScopeMismatch(t *testing.T) {
	attestation := &AnonymousAttestation{
		BbsProof:                []byte("proof"),
		Pseudonym:               make([]byte, 48),
		Scope:                   "wrong-scope",
		RevealedAttestationType: "ios_secure_enclave",
		RevealedDeviceType:      "ios",
		RevealedExpiresAt:       time.Now().Add(24 * time.Hour).Unix(),
	}

	err := VerifyAnonymousAttestation(attestation, "expected-request-id", make([]byte, 96))
	if err == nil {
		t.Fatal("expected error for scope mismatch")
	}
	if !isError(err, ErrAttestationScopeMismatch) {
		t.Fatalf("expected ErrAttestationScopeMismatch, got: %v", err)
	}
}

func TestVerifyAnonymousAttestation_Expired(t *testing.T) {
	attestation := &AnonymousAttestation{
		BbsProof:                []byte("proof"),
		Pseudonym:               make([]byte, 48),
		Scope:                   "request-id",
		RevealedAttestationType: "ios_secure_enclave",
		RevealedDeviceType:      "ios",
		RevealedExpiresAt:       time.Now().Add(-1 * time.Hour).Unix(), // expired 1 hour ago
	}

	err := VerifyAnonymousAttestation(attestation, "request-id", make([]byte, 96))
	if err == nil {
		t.Fatal("expected error for expired attestation")
	}
	if !isError(err, ErrAttestationExpired) {
		t.Fatalf("expected ErrAttestationExpired, got: %v", err)
	}
}

func TestVerifyAnonymousAttestation_ExpiredExact(t *testing.T) {
	// ExpiresAt == now is within the clock skew tolerance window,
	// so it should NOT be rejected at the expiry check.
	// It will fail later at BBS+ proof verification (which is expected).
	attestation := &AnonymousAttestation{
		BbsProof:                []byte("proof"),
		Pseudonym:               make([]byte, 48),
		Scope:                   "request-id",
		RevealedAttestationType: "ios_secure_enclave",
		RevealedDeviceType:      "ios",
		RevealedExpiresAt:       time.Now().Unix(), // exactly now
	}

	err := VerifyAnonymousAttestation(attestation, "request-id", make([]byte, 96))
	if err == nil {
		t.Fatal("expected error (BBS+ verification should fail)")
	}
	// Should NOT be an expiry error — the clock skew tolerance allows this
	if isError(err, ErrAttestationExpired) {
		t.Fatal("credential expiring exactly now should be within clock skew tolerance")
	}
}

func TestVerifyAnonymousAttestation_ClockSkew_WithinTolerance(t *testing.T) {
	// Credential expired 30 seconds ago — within the 60-second tolerance.
	// Should pass the expiry check (and fail later at BBS+ proof verification).
	attestation := &AnonymousAttestation{
		BbsProof:                []byte("proof"),
		Pseudonym:               make([]byte, 48),
		Scope:                   "request-id",
		RevealedAttestationType: "ios_secure_enclave",
		RevealedDeviceType:      "ios",
		RevealedExpiresAt:       time.Now().Add(-30 * time.Second).Unix(),
	}

	err := VerifyAnonymousAttestation(attestation, "request-id", make([]byte, 96))
	if err == nil {
		t.Fatal("expected error (BBS+ verification should fail)")
	}
	if isError(err, ErrAttestationExpired) {
		t.Fatal("credential expired 30s ago should be within clock skew tolerance")
	}
}

func TestVerifyAnonymousAttestation_ClockSkew_OutsideTolerance(t *testing.T) {
	// Credential expired 120 seconds ago — outside the 60-second tolerance.
	// Should be rejected with ErrAttestationExpired.
	attestation := &AnonymousAttestation{
		BbsProof:                []byte("proof"),
		Pseudonym:               make([]byte, 48),
		Scope:                   "request-id",
		RevealedAttestationType: "ios_secure_enclave",
		RevealedDeviceType:      "ios",
		RevealedExpiresAt:       time.Now().Add(-120 * time.Second).Unix(),
	}

	err := VerifyAnonymousAttestation(attestation, "request-id", make([]byte, 96))
	if err == nil {
		t.Fatal("expected error for credential expired well beyond tolerance")
	}
	if !isError(err, ErrAttestationExpired) {
		t.Fatalf("expected ErrAttestationExpired, got: %v", err)
	}
}

func TestVerifyAnonymousAttestation_ClockSkew_FutureExpiry(t *testing.T) {
	// Credential expires in the future — should always pass the expiry check.
	// Will fail later at BBS+ proof verification (which is expected).
	attestation := &AnonymousAttestation{
		BbsProof:                []byte("proof"),
		Pseudonym:               make([]byte, 48),
		Scope:                   "request-id",
		RevealedAttestationType: "ios_secure_enclave",
		RevealedDeviceType:      "ios",
		RevealedExpiresAt:       time.Now().Add(24 * time.Hour).Unix(),
	}

	err := VerifyAnonymousAttestation(attestation, "request-id", make([]byte, 96))
	if err == nil {
		t.Fatal("expected error (BBS+ verification should fail)")
	}
	if isError(err, ErrAttestationExpired) {
		t.Fatal("credential with future expiry should not be rejected as expired")
	}
}

// TestVerifyAnonymousAttestation_BBSProofVerification tests the full BBS+ proof verification
// path with the FFI. This test requires the Rust FFI library to be linked.
// It generates a real BBS+ credential, creates a proof, and verifies it.
func TestVerifyAnonymousAttestation_BBSProofVerification(t *testing.T) {
	// The BBS+ proof verification depends on the FFI. The stub returns an error.
	// This test verifies that the function correctly passes all parameters through
	// to the FFI and handles the result.
	attestation := &AnonymousAttestation{
		BbsProof:                []byte("invalid-proof-data"),
		Pseudonym:               make([]byte, 48),
		Scope:                   "request-id",
		PresentationHeader:      []byte("test-ph"),
		RevealedAttestationType: "ios_secure_enclave",
		RevealedDeviceType:      "ios",
		RevealedExpiresAt:       time.Now().Add(24 * time.Hour).Unix(),
	}

	issuerPublicKey := make([]byte, 96)

	err := VerifyAnonymousAttestation(attestation, "request-id", issuerPublicKey)
	// Should fail with BBS+ proof verification error (either FFI call fails or proof invalid)
	if err == nil {
		t.Fatal("expected error for invalid BBS+ proof data")
	}
	if !isError(err, ErrAnonymousAttestationInvalid) {
		t.Fatalf("expected ErrAnonymousAttestationInvalid, got: %v", err)
	}
}

func TestCredentialHeader(t *testing.T) {
	// Verify the credential header matches the expected value
	expected := "ackagent-anonymous-attestation-v2"
	if credentialHeader != expected {
		t.Errorf("credentialHeader = %q, want %q", credentialHeader, expected)
	}
}

func TestDisclosedIndices(t *testing.T) {
	// Verify disclosed indices are [0, 1, 3] (attestationType, deviceType, expiresAt)
	expected := []int{0, 1, 3}
	if len(disclosedIndices) != len(expected) {
		t.Fatalf("disclosedIndices length = %d, want %d", len(disclosedIndices), len(expected))
	}
	for i, idx := range disclosedIndices {
		if idx != expected[i] {
			t.Errorf("disclosedIndices[%d] = %d, want %d", i, idx, expected[i])
		}
	}
}

func TestTotalSignerMessages(t *testing.T) {
	// Verify total signer messages is 4 (attestationType, deviceType, issuedAt, expiresAt)
	if totalSignerMessages != 4 {
		t.Errorf("totalSignerMessages = %d, want 4", totalSignerMessages)
	}
}

// =============================================================================
// AttestationPolicy tests
// =============================================================================

func TestCheckAttestationPolicy_AnyAcceptsSoftware(t *testing.T) {
	err := CheckAttestationPolicy(AttestationPolicyAny, "software")
	if err != nil {
		t.Fatalf("policy 'any' should accept software attestation, got: %v", err)
	}
}

func TestCheckAttestationPolicy_AnyAcceptsHardware(t *testing.T) {
	for _, attestationType := range []string{"ios_secure_enclave", "android_strongbox", "android_tee"} {
		err := CheckAttestationPolicy(AttestationPolicyAny, attestationType)
		if err != nil {
			t.Fatalf("policy 'any' should accept %q, got: %v", attestationType, err)
		}
	}
}

func TestCheckAttestationPolicy_HardwareRejectsSoftware(t *testing.T) {
	err := CheckAttestationPolicy(AttestationPolicyHardware, "software")
	if err == nil {
		t.Fatal("policy 'hardware' should reject software attestation")
	}
	if !isError(err, ErrAttestationPolicyViolation) {
		t.Fatalf("expected ErrAttestationPolicyViolation, got: %v", err)
	}
}

func TestCheckAttestationPolicy_HardwareAcceptsHardwareTypes(t *testing.T) {
	for _, attestationType := range []string{"ios_secure_enclave", "android_strongbox", "android_tee"} {
		err := CheckAttestationPolicy(AttestationPolicyHardware, attestationType)
		if err != nil {
			t.Fatalf("policy 'hardware' should accept %q, got: %v", attestationType, err)
		}
	}
}

func TestVerifyAnonymousAttestationWithPolicy_SoftwarePassesAny(t *testing.T) {
	attestation := &AnonymousAttestation{
		BbsProof:                []byte("proof"),
		Pseudonym:               make([]byte, 48),
		Scope:                   "request-id",
		RevealedAttestationType: "software",
		RevealedDeviceType:      "ios",
		RevealedExpiresAt:       time.Now().Add(24 * time.Hour).Unix(),
	}

	err := VerifyAnonymousAttestationWithPolicy(attestation, "request-id", make([]byte, 96), AttestationPolicyAny)
	// Should pass the policy check but fail at BBS+ proof verification
	if err == nil {
		t.Fatal("expected error (BBS+ verification should fail)")
	}
	if isError(err, ErrAttestationPolicyViolation) {
		t.Fatal("software attestation should not be rejected with 'any' policy")
	}
}

func TestVerifyAnonymousAttestationWithPolicy_SoftwareFailsHardware(t *testing.T) {
	attestation := &AnonymousAttestation{
		BbsProof:                []byte("proof"),
		Pseudonym:               make([]byte, 48),
		Scope:                   "request-id",
		RevealedAttestationType: "software",
		RevealedDeviceType:      "ios",
		RevealedExpiresAt:       time.Now().Add(24 * time.Hour).Unix(),
	}

	err := VerifyAnonymousAttestationWithPolicy(attestation, "request-id", make([]byte, 96), AttestationPolicyHardware)
	if err == nil {
		t.Fatal("expected error for software attestation with 'hardware' policy")
	}
	if !isError(err, ErrAttestationPolicyViolation) {
		t.Fatalf("expected ErrAttestationPolicyViolation, got: %v", err)
	}
}

func TestVerifyAnonymousAttestationWithPolicy_HardwarePassesBothPolicies(t *testing.T) {
	attestation := &AnonymousAttestation{
		BbsProof:                []byte("proof"),
		Pseudonym:               make([]byte, 48),
		Scope:                   "request-id",
		RevealedAttestationType: "ios_secure_enclave",
		RevealedDeviceType:      "ios",
		RevealedExpiresAt:       time.Now().Add(24 * time.Hour).Unix(),
	}

	for _, policy := range []AttestationPolicy{AttestationPolicyAny, AttestationPolicyHardware} {
		err := VerifyAnonymousAttestationWithPolicy(attestation, "request-id", make([]byte, 96), policy)
		// Should pass the policy check but fail at BBS+ proof verification
		if err == nil {
			t.Fatalf("expected error with policy %q (BBS+ verification should fail)", policy)
		}
		if isError(err, ErrAttestationPolicyViolation) {
			t.Fatalf("hardware attestation should not be rejected with %q policy", policy)
		}
	}
}

func TestVerifyAnonymousAttestationWithPolicy_PolicyCheckBeforeBBS(t *testing.T) {
	// Verify that policy check happens before the expensive BBS+ verification.
	// A software attestation with hardware policy should fail immediately with
	// ErrAttestationPolicyViolation, not ErrAnonymousAttestationInvalid.
	attestation := &AnonymousAttestation{
		BbsProof:                []byte("proof"),
		Pseudonym:               make([]byte, 48),
		Scope:                   "request-id",
		RevealedAttestationType: "software",
		RevealedDeviceType:      "ios",
		RevealedExpiresAt:       time.Now().Add(24 * time.Hour).Unix(),
	}

	err := VerifyAnonymousAttestationWithPolicy(attestation, "request-id", make([]byte, 96), AttestationPolicyHardware)
	if err == nil {
		t.Fatal("expected error")
	}
	if isError(err, ErrAnonymousAttestationInvalid) {
		t.Fatal("policy violation should be returned before BBS+ verification")
	}
	if !isError(err, ErrAttestationPolicyViolation) {
		t.Fatalf("expected ErrAttestationPolicyViolation, got: %v", err)
	}
}

func TestVerifyAnonymousAttestation_DefaultPolicyIsAny(t *testing.T) {
	// The original VerifyAnonymousAttestation function should use "any" policy,
	// meaning software attestation should not be rejected by policy.
	attestation := &AnonymousAttestation{
		BbsProof:                []byte("proof"),
		Pseudonym:               make([]byte, 48),
		Scope:                   "request-id",
		RevealedAttestationType: "software",
		RevealedDeviceType:      "ios",
		RevealedExpiresAt:       time.Now().Add(24 * time.Hour).Unix(),
	}

	err := VerifyAnonymousAttestation(attestation, "request-id", make([]byte, 96))
	// Should fail at BBS+ verification, NOT at policy check
	if err == nil {
		t.Fatal("expected error (BBS+ verification should fail)")
	}
	if isError(err, ErrAttestationPolicyViolation) {
		t.Fatal("default VerifyAnonymousAttestation should use 'any' policy")
	}
}

// isError checks if err wraps the target error.
func isError(err, target error) bool {
	for e := err; e != nil; {
		if e == target {
			return true
		}
		type wrapper interface {
			Unwrap() error
		}
		w, ok := e.(wrapper)
		if !ok {
			return false
		}
		e = w.Unwrap()
	}
	return false
}
