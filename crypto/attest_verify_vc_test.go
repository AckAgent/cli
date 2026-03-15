package crypto

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestAnonymousAttestationFromW3CEnvelope_ParseValid(t *testing.T) {
	proofHex := "deadbeef"
	pseudonym := []byte("012345678901234567890123456789012345678901234567")
	presentationHeader := []byte("request-123")

	envelope := map[string]any{
		"@context": []string{
			"https://www.w3.org/ns/credentials/v2",
		},
		"type": []string{"VerifiablePresentation"},
		"proof": map[string]any{
			"type":        "DataIntegrityProof",
			"cryptosuite": "bbs-2023",
			"proofValue":  "u" + base64.RawURLEncoding.EncodeToString(mustDecodeHex(t, proofHex)),
		},
		"ackagentAnonymousAttestation": map[string]any{
			"pseudonym":          base64.StdEncoding.EncodeToString(pseudonym),
			"scope":              "request-123",
			"presentationHeader": base64.StdEncoding.EncodeToString(presentationHeader),
			"revealedMessages": map[string]any{
				"attestationType": "android_strongbox",
				"deviceType":      "android",
				"expiresAt":       int64(2_200_000_000),
			},
		},
	}

	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}

	attestation, err := AnonymousAttestationFromW3CEnvelope(raw)
	if err != nil {
		t.Fatalf("expected parse success, got error: %v", err)
	}

	if got := hex.EncodeToString(attestation.BbsProof); got != proofHex {
		t.Fatalf("proof mismatch: got %s want %s", got, proofHex)
	}
	if got := string(attestation.Pseudonym); got != string(pseudonym) {
		t.Fatalf("pseudonym mismatch")
	}
	if got := string(attestation.PresentationHeader); got != string(presentationHeader) {
		t.Fatalf("presentation header mismatch")
	}
	if attestation.Scope != "request-123" {
		t.Fatalf("scope mismatch: got %q", attestation.Scope)
	}
}

func TestW3CAnonymousAttestationEnvelopeFromNative_RoundTrip(t *testing.T) {
	native := &AnonymousAttestation{
		BbsProof:                mustDecodeHex(t, "00112233"),
		Pseudonym:               []byte("012345678901234567890123456789012345678901234567"),
		Scope:                   "request-456",
		PresentationHeader:      []byte("request-456"),
		RevealedAttestationType: "ios_secure_enclave",
		RevealedDeviceType:      "ios",
		RevealedExpiresAt:       2_200_000_000,
	}

	envelopeJSON, err := W3CAnonymousAttestationEnvelopeFromNative(native)
	if err != nil {
		t.Fatalf("marshal native to W3C: %v", err)
	}

	parsed, err := AnonymousAttestationFromW3CEnvelope(envelopeJSON)
	if err != nil {
		t.Fatalf("parse generated envelope: %v", err)
	}

	if got := hex.EncodeToString(parsed.BbsProof); got != hex.EncodeToString(native.BbsProof) {
		t.Fatalf("proof mismatch: got %s want %s", got, hex.EncodeToString(native.BbsProof))
	}
	if string(parsed.Pseudonym) != string(native.Pseudonym) {
		t.Fatalf("pseudonym mismatch")
	}
	if parsed.Scope != native.Scope {
		t.Fatalf("scope mismatch: got %q want %q", parsed.Scope, native.Scope)
	}
}

func TestW3CAnonymousAttestationEnvelopeFromNative_Nil(t *testing.T) {
	_, err := W3CAnonymousAttestationEnvelopeFromNative(nil)
	if err == nil {
		t.Fatal("expected error for nil attestation")
	}
}

func TestAnonymousAttestationFromW3CEnvelope_UnsupportedCryptosuite(t *testing.T) {
	raw := []byte(`{
		"@context":["https://www.w3.org/ns/credentials/v2"],
		"type":["VerifiablePresentation"],
		"proof":{"type":"DataIntegrityProof","cryptosuite":"eddsa-2022","proofValue":"uAA"},
		"ackagentAnonymousAttestation":{
			"pseudonym":"AA==",
			"scope":"request-123",
			"presentationHeader":"AA==",
			"revealedMessages":{"attestationType":"software","deviceType":"ios","expiresAt":2200000000}
		}
	}`)

	_, err := AnonymousAttestationFromW3CEnvelope(raw)
	if err == nil {
		t.Fatal("expected error for unsupported cryptosuite")
	}
}

func TestAnonymousAttestationFromW3CEnvelope_MissingScope(t *testing.T) {
	raw := []byte(`{
		"@context":["https://www.w3.org/ns/credentials/v2"],
		"type":["VerifiablePresentation"],
		"proof":{"type":"DataIntegrityProof","cryptosuite":"bbs-2023","proofValue":"uAA"},
		"ackagentAnonymousAttestation":{
			"pseudonym":"AA==",
			"scope":"",
			"presentationHeader":"AA==",
			"revealedMessages":{"attestationType":"software","deviceType":"ios","expiresAt":2200000000}
		}
	}`)

	_, err := AnonymousAttestationFromW3CEnvelope(raw)
	if err == nil {
		t.Fatal("expected error for missing scope")
	}
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return decoded
}
