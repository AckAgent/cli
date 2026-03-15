package transport

import (
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/ackagent/cli/crypto"
)

// IssuerKeyInfo holds an issuer public key and its identifier.
type IssuerKeyInfo struct {
	ID        string
	PublicKey []byte
}

// attestationWrapper is used for partial JSON unmarshal to extract the attestation
// and error fields from any response type without knowing the full response structure.
type attestationWrapper struct {
	Attestation json.RawMessage `json:"attestation"`
	ErrorCode   *int            `json:"errorCode"`
}

// attestationKeyHint extracts the issuerPublicKeyId from a W3C attestation envelope.
type attestationKeyHint struct {
	AckagentAnonymousAttestation struct {
		IssuerPublicKeyID string `json:"issuerPublicKeyId"`
	} `json:"ackagentAnonymousAttestation"`
}

// VerifyAttestationFromJSON extracts and verifies anonymous attestation from
// a decrypted response JSON blob. This works for any response type that contains
// an "attestation" field.
//
// If skip is true, verification is bypassed entirely.
// If issuerKeys is empty, verification is skipped (no cached key available).
// Otherwise, the attestation field must be present and valid.
//
// Key selection:
//  1. If the attestation contains an issuerPublicKeyId and a matching key exists, use it.
//  2. If no key ID is present (old mobile app), try each key in order.
//  3. If no key matches, return the last verification error.
func VerifyAttestationFromJSON(decrypted []byte, requestID string, issuerKeys []IssuerKeyInfo, skip bool) error {
	if skip {
		return nil
	}

	if len(issuerKeys) == 0 {
		slog.Warn("BBS+ issuer public keys list is empty", "request_id", requestID)
		// No issuer key cached yet — skip verification.
		// This can happen on first request before the key is fetched.
		return nil
	}

	var wrapper attestationWrapper
	if err := json.Unmarshal(decrypted, &wrapper); err != nil {
		return fmt.Errorf("failed to parse response for attestation: %w", err)
	}

	// Rejection/error responses don't include attestation — skip verification.
	if wrapper.ErrorCode != nil {
		return nil
	}

	if len(wrapper.Attestation) == 0 || string(wrapper.Attestation) == "null" {
		return fmt.Errorf("missing anonymous attestation in approval response")
	}

	// Try to extract the key ID hint from the attestation envelope.
	var hint attestationKeyHint
	_ = json.Unmarshal(wrapper.Attestation, &hint) // best-effort parse
	keyIDHint := hint.AckagentAnonymousAttestation.IssuerPublicKeyID

	// Build candidate key list based on key ID hint.
	candidates := selectCandidateKeys(issuerKeys, keyIDHint)

	var lastErr error
	for _, candidate := range candidates {
		if err := crypto.VerifyAnonymousAttestationW3CEnvelope(
			wrapper.Attestation,
			requestID,
			candidate.PublicKey,
		); err != nil {
			lastErr = err
			continue
		}
		return nil
	}

	if lastErr != nil {
		return fmt.Errorf("anonymous attestation verification failed: %w", lastErr)
	}
	return fmt.Errorf("no matching issuer key for attestation verification")
}

// selectCandidateKeys returns keys to try for verification.
// If keyIDHint is non-empty and a matching key exists, only that key is returned.
// Otherwise, all keys are returned for fallback trial.
func selectCandidateKeys(keys []IssuerKeyInfo, keyIDHint string) []IssuerKeyInfo {
	if keyIDHint != "" {
		for _, k := range keys {
			if k.ID == keyIDHint {
				return []IssuerKeyInfo{k}
			}
		}
		// Key ID present but no match — still try all keys as fallback.
		slog.Warn("attestation key ID hint not found in local keys, trying all",
			"hint", keyIDHint)
	}
	return keys
}
