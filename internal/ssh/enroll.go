package ssh

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/ackagent/cli/crypto"
	protocol "github.com/ackagent/api/go/protocol"
	"github.com/ackagent/cli/internal/shared/config"
	"github.com/ackagent/cli/internal/shared/log"
	"github.com/ackagent/cli/internal/shared/sysinfo"
	"github.com/ackagent/cli/internal/shared/transport"
)

var sshLog = log.New("ssh")

// buildEnrollPayload validates the algorithm and constructs the enrollment payload.
func buildEnrollPayload(label, algorithm string, processInfo sysinfo.ProcessInfo) ([]byte, error) {
	// Validate and normalize algorithm
	if algorithm == "" {
		algorithm = config.AlgorithmP256
	}
	if algorithm != config.AlgorithmP256 && algorithm != config.AlgorithmEd25519 {
		return nil, fmt.Errorf("unsupported algorithm: %s (use 'ecdsa' or 'ed25519')", algorithm)
	}

	algDisplay := "ECDSA P-256"
	if algorithm == config.AlgorithmEd25519 {
		algDisplay = "Ed25519"
	}
	fields := []protocol.DisplayField{
		{Label: "Algorithm", Value: algDisplay},
		{Label: "Label", Value: label},
	}

	icon := "key.fill"
	historyTitle := "SSH Key Enrolled"
	subtitle := "SSH key enrollment"
	payload := protocol.EnrollPayload{
		Type:       protocol.Enroll,
		Purpose:    protocol.Ssh,
		Label:      &label,
		Algorithm:  &algorithm,
		SourceInfo: processInfo.ToSourceInfo(),
		Display: &protocol.GenericDisplaySchema{
			Title:        "Enroll SSH Key?",
			HistoryTitle: &historyTitle,
			Subtitle:     &subtitle,
			Icon:         &icon,
			Fields:       fields,
		},
	}

	return json.Marshal(payload)
}

// parseEnrollResponse parses the decrypted enrollment response and constructs key metadata.
func parseEnrollResponse(decrypted []byte, requestedAlgorithm, label string) (*config.KeyMetadata, error) {
	response, err := transport.ParseEnrollResponse(decrypted)
	if err != nil {
		return nil, err
	}

	// Use algorithm from response if provided, otherwise use requested algorithm
	respAlgorithm := requestedAlgorithm
	if response.Algorithm != nil && *response.Algorithm != "" {
		respAlgorithm = *response.Algorithm
	}

	if response.PublicKeyHex == nil {
		return nil, fmt.Errorf("response missing public key")
	}
	publicKey, err := hex.DecodeString(*response.PublicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid public key hex: %w", err)
	}

	switch respAlgorithm {
	case config.AlgorithmP256:
		switch len(publicKey) {
		case 33:
			if publicKey[0] != 0x02 && publicKey[0] != 0x03 {
				return nil, fmt.Errorf("invalid P-256 compressed key prefix: 0x%02x", publicKey[0])
			}
		case 65:
			if publicKey[0] != 0x04 {
				return nil, fmt.Errorf("invalid P-256 uncompressed key prefix: 0x%02x", publicKey[0])
			}
			compressed, err := crypto.CompressPublicKey(publicKey)
			if err != nil {
				return nil, fmt.Errorf("failed to compress P-256 public key: %w", err)
			}
			publicKey = compressed
		default:
			return nil, fmt.Errorf("invalid P-256 public key length: expected 33 (compressed), got %d", len(publicKey))
		}
	case config.AlgorithmEd25519:
		if len(publicKey) != 32 {
			return nil, fmt.Errorf("invalid Ed25519 public key length: expected 32, got %d", len(publicKey))
		}
	default:
		return nil, fmt.Errorf("unsupported algorithm in response: %s", respAlgorithm)
	}

	// Public key hex for display/logging
	publicKeyHex := *response.PublicKeyHex

	iosKeyID := ""
	if response.IosKeyId != nil {
		iosKeyID = *response.IosKeyId
	}

	keyMeta := &config.KeyMetadata{
		IOSKeyID:  iosKeyID,
		Label:     label,
		PublicKey: publicKey,
		Algorithm: respAlgorithm,
		Purpose:   config.KeyPurposeSSH,
		CreatedAt: time.Now(),
	}

	if response.Attestation != nil {
		a := response.Attestation
		attestedPubKey, _ := hex.DecodeString(a.PublicKeyHex)
		keyMeta.Attestation = &config.KeyMetadataAttestation{
			PublicKey:            attestedPubKey,
			Assertion:            a.Assertion,
			AttestationType:      string(a.AttestationType),
			Challenge:            a.Challenge,
			AttestationTimestamp: a.AttestationTimestamp,
		}
		if a.AttestationObject != nil {
			keyMeta.Attestation.AttestationObject = *a.AttestationObject
		}
		if a.AttestationPublicKeyHex != nil {
			attestPubKey, _ := hex.DecodeString(*a.AttestationPublicKeyHex)
			keyMeta.Attestation.AttestationPublicKey = attestPubKey
		}
	}

	sshLog.Debug("SSH key enrolled: %s (%s)", publicKeyHex, respAlgorithm)
	return keyMeta, nil
}

// EnrollSSHKey sends an enrollment request to generate an SSH key on iOS.
// Returns the key metadata on success.
// Algorithm can be "ecdsa" (default) or "ed25519".
func EnrollSSHKey(cfg *config.Config, label string, algorithm string) (*config.KeyMetadata, error) {
	ctx := context.Background()

	// Validate algorithm early (buildEnrollPayload normalizes empty → P256)
	normalizedAlg := algorithm
	if normalizedAlg == "" {
		normalizedAlg = config.AlgorithmP256
	}

	// Build enrollment payload
	processInfo := sysinfo.GetProcessInfo()
	payloadBytes, err := buildEnrollPayload(label, algorithm, processInfo)
	if err != nil {
		return nil, err
	}

	sshLog.Debug("sending SSH key enrollment request")

	sshLog.Debug("waiting for iOS approval...")
	fmt.Fprintf(os.Stderr, "Approve key generation on iOS device...\n")

	result, err := transport.NewRequestBuilder(cfg).
		WithTimeout(config.DefaultSigningTimeout).
		WithExpiration(int(config.DefaultSigningTimeout.Seconds())).
		Send(ctx, json.RawMessage(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("enrollment request failed: %w", err)
	}

	switch result.Response.Status {
	case "responded":
		// Continue to decrypt
	case "expired":
		return nil, fmt.Errorf("enrollment request expired")
	default:
		return nil, fmt.Errorf("unexpected status: %s", result.Response.Status)
	}

	decrypted, err := result.DecryptWithoutAttestation()
	if err != nil {
		return nil, fmt.Errorf("enrollment request failed: %w", err)
	}

	return parseEnrollResponse(decrypted, normalizedAlg, label)
}
