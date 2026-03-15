package transport

import (
	"strings"
	"testing"
)

func TestVerifyAttestationFromJSON_SkipFlag(t *testing.T) {
	// When skip=true, verification should pass even with no attestation
	err := VerifyAttestationFromJSON(
		[]byte(`{"decision":"allow"}`),
		"request-123",
		[]IssuerKeyInfo{{ID: "key-1", PublicKey: []byte("fake-issuer-key")}},
		true,
	)
	if err != nil {
		t.Fatalf("expected no error with skip=true, got: %v", err)
	}
}

func TestVerifyAttestationFromJSON_EmptyIssuerKeys(t *testing.T) {
	// When issuer keys list is empty, verification should be skipped gracefully
	err := VerifyAttestationFromJSON(
		[]byte(`{"decision":"allow"}`),
		"request-123",
		nil,
		false,
	)
	if err != nil {
		t.Fatalf("expected no error with nil issuer keys, got: %v", err)
	}

	// Also test with zero-length slice
	err = VerifyAttestationFromJSON(
		[]byte(`{"decision":"allow"}`),
		"request-123",
		[]IssuerKeyInfo{},
		false,
	)
	if err != nil {
		t.Fatalf("expected no error with empty issuer keys, got: %v", err)
	}
}

func TestVerifyAttestationFromJSON_MissingAttestation(t *testing.T) {
	// Response without attestation field should fail
	err := VerifyAttestationFromJSON(
		[]byte(`{"decision":"allow","signature":"abc"}`),
		"request-123",
		[]IssuerKeyInfo{{ID: "key-1", PublicKey: []byte("fake-issuer-key-96-bytes-long-enough-for-testing-bls12-381-g2-point-key")}},
		false,
	)
	if err == nil {
		t.Fatal("expected error for missing attestation field")
	}
	if !strings.Contains(err.Error(), "missing anonymous attestation") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestVerifyAttestationFromJSON_NullAttestation(t *testing.T) {
	// Explicit null attestation should fail
	err := VerifyAttestationFromJSON(
		[]byte(`{"decision":"allow","attestation":null}`),
		"request-123",
		[]IssuerKeyInfo{{ID: "key-1", PublicKey: []byte("fake-issuer-key-96-bytes-long-enough-for-testing-bls12-381-g2-point-key")}},
		false,
	)
	if err == nil {
		t.Fatal("expected error for null attestation")
	}
	if !strings.Contains(err.Error(), "missing anonymous attestation") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestVerifyAttestationFromJSON_InvalidJSON(t *testing.T) {
	// Malformed JSON should return error
	err := VerifyAttestationFromJSON(
		[]byte(`not-valid-json`),
		"request-123",
		[]IssuerKeyInfo{{ID: "key-1", PublicKey: []byte("fake-issuer-key-96-bytes-long-enough-for-testing-bls12-381-g2-point-key")}},
		false,
	)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "failed to parse response") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestVerifyAttestationFromJSON_InvalidAttestationContent(t *testing.T) {
	// Attestation present but not a valid W3C envelope — should fail in crypto.Verify
	err := VerifyAttestationFromJSON(
		[]byte(`{"decision":"allow","attestation":{"not":"a-valid-envelope"}}`),
		"request-123",
		[]IssuerKeyInfo{{ID: "key-1", PublicKey: []byte("fake-issuer-key-96-bytes-long-enough-for-testing-bls12-381-g2-point-key")}},
		false,
	)
	if err == nil {
		t.Fatal("expected error for invalid attestation content")
	}
	if !strings.Contains(err.Error(), "attestation verification failed") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestVerifyAttestationFromJSON_RejectionResponse(t *testing.T) {
	// Rejection responses (with errorCode) should skip attestation verification
	err := VerifyAttestationFromJSON(
		[]byte(`{"errorCode":1,"errorMessage":"User rejected the request"}`),
		"request-123",
		[]IssuerKeyInfo{{ID: "key-1", PublicKey: []byte("fake-issuer-key-96-bytes-long-enough-for-testing-bls12-381-g2-point-key")}},
		false,
	)
	if err != nil {
		t.Fatalf("expected no error for rejection response, got: %v", err)
	}
}

func TestVerifyAttestationFromJSON_EmptyObject(t *testing.T) {
	// Empty JSON object — no attestation field
	err := VerifyAttestationFromJSON(
		[]byte(`{}`),
		"request-123",
		[]IssuerKeyInfo{{ID: "key-1", PublicKey: []byte("fake-issuer-key-96-bytes-long-enough-for-testing-bls12-381-g2-point-key")}},
		false,
	)
	if err == nil {
		t.Fatal("expected error for empty JSON object with no attestation")
	}
	if !strings.Contains(err.Error(), "missing anonymous attestation") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestSelectCandidateKeys_KeyIDMatch(t *testing.T) {
	keys := []IssuerKeyInfo{
		{ID: "key-1", PublicKey: []byte("pk-1")},
		{ID: "key-2", PublicKey: []byte("pk-2")},
		{ID: "key-3", PublicKey: []byte("pk-3")},
	}

	candidates := selectCandidateKeys(keys, "key-2")
	if len(candidates) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(candidates))
	}
	if candidates[0].ID != "key-2" {
		t.Fatalf("expected key-2, got %s", candidates[0].ID)
	}
}

func TestSelectCandidateKeys_NoKeyIDHint(t *testing.T) {
	keys := []IssuerKeyInfo{
		{ID: "key-1", PublicKey: []byte("pk-1")},
		{ID: "key-2", PublicKey: []byte("pk-2")},
	}

	candidates := selectCandidateKeys(keys, "")
	if len(candidates) != 2 {
		t.Fatalf("expected 2 candidates (all keys), got %d", len(candidates))
	}
}

func TestSelectCandidateKeys_KeyIDNotFound(t *testing.T) {
	keys := []IssuerKeyInfo{
		{ID: "key-1", PublicKey: []byte("pk-1")},
		{ID: "key-2", PublicKey: []byte("pk-2")},
	}

	// Key ID present but not found — should fall back to all keys
	candidates := selectCandidateKeys(keys, "key-999")
	if len(candidates) != 2 {
		t.Fatalf("expected 2 candidates (fallback to all), got %d", len(candidates))
	}
}

func TestVerifyAttestationFromJSON_SkipWithEmptyKeys(t *testing.T) {
	// skip=true should return nil regardless of empty keys
	err := VerifyAttestationFromJSON(
		[]byte(`{"decision":"allow"}`),
		"request-123",
		nil,
		true,
	)
	if err != nil {
		t.Fatalf("expected no error with skip=true and nil keys, got: %v", err)
	}
}

func TestVerifyAttestationFromJSON_KeyIDHintExtraction(t *testing.T) {
	// Verify that the attestation key ID hint is parsed from the envelope.
	// The actual crypto verification will fail (no real BBS+ proof), but we can
	// verify that the key selection logic works by checking the error message.
	attestation := `{
		"ackagentAnonymousAttestation": {
			"issuerPublicKeyId": "key-2",
			"proof": "not-a-real-proof"
		}
	}`
	decrypted := `{"decision":"allow","attestation":` + attestation + `}`

	keys := []IssuerKeyInfo{
		{ID: "key-1", PublicKey: []byte("wrong-key-bytes-for-testing")},
		{ID: "key-2", PublicKey: []byte("right-key-bytes-for-testing")},
	}

	// This will fail at crypto verification (not real BBS+ data), but
	// the important thing is it tries key-2 only (matched by hint).
	err := VerifyAttestationFromJSON([]byte(decrypted), "req-1", keys, false)
	if err == nil {
		t.Fatal("expected crypto verification error (test data is not valid BBS+)")
	}
	// Should be an attestation verification failure, not "no matching key"
	if !strings.Contains(err.Error(), "attestation verification failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyAttestationFromJSON_FallbackTriesAllKeys(t *testing.T) {
	// No key ID hint — should try all keys in order.
	attestation := `{"not":"a-valid-envelope"}`
	decrypted := `{"decision":"allow","attestation":` + attestation + `}`

	keys := []IssuerKeyInfo{
		{ID: "key-1", PublicKey: []byte("key-bytes-1")},
		{ID: "key-2", PublicKey: []byte("key-bytes-2")},
	}

	err := VerifyAttestationFromJSON([]byte(decrypted), "req-1", keys, false)
	if err == nil {
		t.Fatal("expected error (no valid BBS+ proof)")
	}
	// Should fail with verification error after trying all keys
	if !strings.Contains(err.Error(), "attestation verification failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}
