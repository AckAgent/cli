package crypto

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// DataIntegrityProof represents the minimal W3C Data Integrity proof shape
// needed for bbs-2023 anonymous attestation envelopes.
type DataIntegrityProof struct {
	Type        string `json:"type"`
	Cryptosuite string `json:"cryptosuite"`
	ProofValue  string `json:"proofValue"`
}

// W3CAnonymousAttestationEnvelope is a minimal VC/VP-style wrapper accepted by
// CLI anonymous attestation verification during format migration.
type W3CAnonymousAttestationEnvelope struct {
	Context                      []string           `json:"@context"`
	Type                         any                `json:"type"`
	Proof                        DataIntegrityProof `json:"proof"`
	AckAgentAnonymousAttestation W3CAttestationBody `json:"ackagentAnonymousAttestation"`
}

// W3CAttestationBody contains AckAgent-specific attestation fields inside a
// W3C Data Integrity envelope.
type W3CAttestationBody struct {
	Pseudonym          string                        `json:"pseudonym"`
	Scope              string                        `json:"scope"`
	PresentationHeader string                        `json:"presentationHeader"`
	RevealedMessages   W3CAttestationRevealedMessage `json:"revealedMessages"`
}

// W3CAttestationRevealedMessage contains disclosed credential messages.
type W3CAttestationRevealedMessage struct {
	AttestationType string `json:"attestationType"`
	DeviceType      string `json:"deviceType"`
	ExpiresAt       int64  `json:"expiresAt"`
}

// W3CAnonymousAttestationEnvelopeFromNative converts a native anonymous
// attestation payload into the canonical W3C/Data-Integrity envelope shape.
func W3CAnonymousAttestationEnvelopeFromNative(
	attestation *AnonymousAttestation,
) ([]byte, error) {
	if attestation == nil {
		return nil, fmt.Errorf("anonymous attestation is nil")
	}
	if attestation.Scope == "" {
		return nil, fmt.Errorf("anonymous attestation scope is required")
	}

	envelope := W3CAnonymousAttestationEnvelope{
		Context: []string{
			"https://www.w3.org/ns/credentials/v2",
			"https://w3id.org/security/data-integrity/v2",
			"https://w3id.org/security/bbs/v1",
			"https://schemas.ackagent.com/credentials/anonymous-attestation/v1",
		},
		Type: []string{
			"VerifiablePresentation",
			"AckAgentAnonymousAttestationPresentation",
		},
		Proof: DataIntegrityProof{
			Type:        "DataIntegrityProof",
			Cryptosuite: "bbs-2023",
			ProofValue:  "u" + base64.RawURLEncoding.EncodeToString(attestation.BbsProof),
		},
		AckAgentAnonymousAttestation: W3CAttestationBody{
			Pseudonym:          base64.StdEncoding.EncodeToString(attestation.Pseudonym),
			Scope:              attestation.Scope,
			PresentationHeader: base64.StdEncoding.EncodeToString(attestation.PresentationHeader),
			RevealedMessages: W3CAttestationRevealedMessage{
				AttestationType: attestation.RevealedAttestationType,
				DeviceType:      attestation.RevealedDeviceType,
				ExpiresAt:       attestation.RevealedExpiresAt,
			},
		},
	}

	raw, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal W3C attestation envelope: %w", err)
	}
	return raw, nil
}

// AnonymousAttestationFromW3CEnvelope parses a W3C/Data-Integrity attestation
// envelope into the native AnonymousAttestation structure.
func AnonymousAttestationFromW3CEnvelope(
	envelopeJSON []byte,
) (*AnonymousAttestation, error) {
	var envelope W3CAnonymousAttestationEnvelope
	if err := json.Unmarshal(envelopeJSON, &envelope); err != nil {
		return nil, fmt.Errorf("failed to parse W3C attestation envelope: %w", err)
	}

	if envelope.Proof.Type != "DataIntegrityProof" {
		return nil, fmt.Errorf("unsupported proof type: %q", envelope.Proof.Type)
	}
	if envelope.Proof.Cryptosuite != "bbs-2023" {
		return nil, fmt.Errorf("unsupported cryptosuite: %q", envelope.Proof.Cryptosuite)
	}
	if envelope.AckAgentAnonymousAttestation.Scope == "" {
		return nil, fmt.Errorf("W3C envelope missing scope")
	}

	bbsProof, err := decodeProofValue(envelope.Proof.ProofValue)
	if err != nil {
		return nil, fmt.Errorf("invalid proofValue: %w", err)
	}

	pseudonym, err := base64.StdEncoding.DecodeString(envelope.AckAgentAnonymousAttestation.Pseudonym)
	if err != nil {
		return nil, fmt.Errorf("invalid pseudonym base64: %w", err)
	}

	presentationHeader, err := base64.StdEncoding.DecodeString(envelope.AckAgentAnonymousAttestation.PresentationHeader)
	if err != nil {
		return nil, fmt.Errorf("invalid presentationHeader base64: %w", err)
	}

	return &AnonymousAttestation{
		BbsProof:                bbsProof,
		Pseudonym:               pseudonym,
		Scope:                   envelope.AckAgentAnonymousAttestation.Scope,
		PresentationHeader:      presentationHeader,
		RevealedAttestationType: envelope.AckAgentAnonymousAttestation.RevealedMessages.AttestationType,
		RevealedDeviceType:      envelope.AckAgentAnonymousAttestation.RevealedMessages.DeviceType,
		RevealedExpiresAt:       envelope.AckAgentAnonymousAttestation.RevealedMessages.ExpiresAt,
	}, nil
}

// VerifyAnonymousAttestationW3CEnvelope parses and verifies a W3C/Data-Integrity
// anonymous attestation envelope using the default "any" attestation policy.
func VerifyAnonymousAttestationW3CEnvelope(
	envelopeJSON []byte,
	requestID string,
	issuerPublicKey []byte,
) error {
	return VerifyAnonymousAttestationW3CEnvelopeWithPolicy(envelopeJSON, requestID, issuerPublicKey, AttestationPolicyAny)
}

// VerifyAnonymousAttestationW3CEnvelopeWithPolicy parses and verifies a W3C/Data-Integrity
// anonymous attestation envelope, enforcing the given attestation type policy.
func VerifyAnonymousAttestationW3CEnvelopeWithPolicy(
	envelopeJSON []byte,
	requestID string,
	issuerPublicKey []byte,
	policy AttestationPolicy,
) error {
	attestation, err := AnonymousAttestationFromW3CEnvelope(envelopeJSON)
	if err != nil {
		return err
	}
	return VerifyAnonymousAttestationWithPolicy(attestation, requestID, issuerPublicKey, policy)
}

func decodeProofValue(value string) ([]byte, error) {
	if value == "" {
		return nil, fmt.Errorf("proofValue is empty")
	}

	// Preferred format: multibase base64url (leading 'u')
	if strings.HasPrefix(value, "u") {
		decoded, err := base64.RawURLEncoding.DecodeString(value[1:])
		if err != nil {
			return nil, err
		}
		return decoded, nil
	}

	if decoded, err := base64.RawURLEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	if decoded, err := base64.URLEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	return base64.StdEncoding.DecodeString(value)
}
