package crypto

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestVerifyAnonymousAttestationW3CEnvelope_BBSVector(t *testing.T) {
	vector := loadBbsPseudonymVector(t, "android-bbs-pseudonym-vector.json")

	scopeBytes, err := hex.DecodeString(vector.ScopeHex)
	if err != nil {
		t.Fatalf("decode scope hex: %v", err)
	}
	scope := string(scopeBytes)

	disclosed := map[int]string{}
	for _, msg := range vector.DisclosedMessages {
		disclosed[msg.Index] = msg.ValueHex
	}

	proofBytes, err := hex.DecodeString(vector.ProofHex)
	if err != nil {
		t.Fatalf("decode proof hex: %v", err)
	}
	pseudonymBytes, err := hex.DecodeString(vector.PseudonymHex)
	if err != nil {
		t.Fatalf("decode pseudonym hex: %v", err)
	}
	phBytes, err := hex.DecodeString(vector.PresentationHeaderHex)
	if err != nil {
		t.Fatalf("decode presentation header hex: %v", err)
	}

	envelope := map[string]any{
		"@context": []string{
			"https://www.w3.org/ns/credentials/v2",
			"https://w3id.org/security/data-integrity/v2",
			"https://w3id.org/security/bbs/v1",
			"https://schemas.ackagent.com/credentials/anonymous-attestation/v1",
		},
		"type": []string{
			"VerifiablePresentation",
			"AckAgentAnonymousAttestationPresentation",
		},
		"proof": map[string]any{
			"type":        "DataIntegrityProof",
			"cryptosuite": "bbs-2023",
			"proofValue":  "u" + base64.RawURLEncoding.EncodeToString(proofBytes),
		},
		"ackagentAnonymousAttestation": map[string]any{
			"pseudonym":          base64.StdEncoding.EncodeToString(pseudonymBytes),
			"scope":              scope,
			"presentationHeader": base64.StdEncoding.EncodeToString(phBytes),
			"revealedMessages": map[string]any{
				"attestationType": mustUtf8FromHex(t, disclosed[0]),
				"deviceType":      mustUtf8FromHex(t, disclosed[1]),
				"expiresAt":       mustInt64FromHex(t, disclosed[3]),
			},
		},
	}

	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}

	issuerPublicKey := decodeHex(t, vector.IssuerPublicKeyHex)
	if err := VerifyAnonymousAttestationW3CEnvelope(raw, scope, issuerPublicKey); err != nil {
		t.Fatalf("expected envelope verification success, got: %v", err)
	}
}

func mustUtf8FromHex(t *testing.T, value string) string {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode utf8 hex: %v", err)
	}
	return string(decoded)
}

func mustInt64FromHex(t *testing.T, value string) int64 {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode int64 hex: %v", err)
	}
	if len(decoded) != 8 {
		t.Fatalf("expected 8-byte int64, got %d", len(decoded))
	}
	var out int64
	for _, b := range decoded {
		out = (out << 8) | int64(b)
	}
	return out
}
