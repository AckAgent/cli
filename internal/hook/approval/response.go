package approval

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/ackagent/cli/crypto"
	protocol "github.com/ackagent/api/go/protocol"
	"github.com/ackagent/cli/internal/shared/config"
	"github.com/ackagent/cli/internal/shared/log"
	"github.com/ackagent/cli/internal/shared/transport"
)

var (
	ErrInvalidSignature = errors.New("invalid signature")
	ErrMissingSignature = errors.New("missing context signature")
)

// ApprovalResponse is an alias for protocol.ClaudeApprovalResponse.
// Use the wrapper methods below for convenient access.
type ApprovalResponse = protocol.ClaudeApprovalResponse

// RememberRule is an alias for protocol.RememberRule.
type RememberRule = protocol.RememberRule

// QuestionResponse is an alias for protocol.ClaudeQuestionResponse.
// Use the wrapper methods below for convenient access.
type QuestionResponse = protocol.ClaudeQuestionResponse

// Helper functions for ApprovalResponse

// getDecision returns the decision as a string.
func getDecision(r *ApprovalResponse) string {
	return string(r.Decision)
}

// getUpdatedInput returns the updated input map, or nil if not present.
func getUpdatedInput(r *ApprovalResponse) map[string]any {
	if r.UpdatedInput == nil {
		return nil
	}
	return *r.UpdatedInput
}

// getErrorCode returns the error code as *int, or nil if not present.
func getErrorCode(r *ApprovalResponse) *int {
	if r.ErrorCode == nil {
		return nil
	}
	code := int(*r.ErrorCode)
	return &code
}

// getErrorMessage returns the error message, or empty string if not present.
func getErrorMessage(r *ApprovalResponse) string {
	if r.ErrorMessage == nil {
		return ""
	}
	return *r.ErrorMessage
}

// Helper functions for RememberRule

// getRulePattern returns the pattern, or empty string if not present.
func getRulePattern(r *RememberRule) string {
	if r.Pattern == nil {
		return ""
	}
	return *r.Pattern
}

// Helper functions for QuestionResponse

// getAnswersBytes returns the answers bytes, or nil if not present.
func getAnswersBytes(r *QuestionResponse) []byte {
	if r.AnswersBytes == nil {
		return nil
	}
	return *r.AnswersBytes
}

// getAnswersSignature returns the answers signature, or nil if not present.
func getAnswersSignature(r *QuestionResponse) []byte {
	if r.AnswersSignature == nil {
		return nil
	}
	return *r.AnswersSignature
}

// getQuestionErrorCode returns the error code as *int, or nil if not present.
func getQuestionErrorCode(r *QuestionResponse) *int {
	if r.ErrorCode == nil {
		return nil
	}
	code := int(*r.ErrorCode)
	return &code
}

// getQuestionErrorMessage returns the error message, or empty string if not present.
func getQuestionErrorMessage(r *QuestionResponse) string {
	if r.ErrorMessage == nil {
		return ""
	}
	return *r.ErrorMessage
}

// processApprovalResponse decrypts and processes the approval response.
func processApprovalResponse(
	resp *transport.Response,
	ephemeralPrivate []byte,
	requestID []byte,
	requestIDString string,
	contextPreimage []byte,
	cfg *config.Config,
) (*ApprovalResult, error) {
	// Decrypt response using shared helper
	decrypted, err := resp.Decrypt(ephemeralPrivate, requestID)
	if err != nil {
		return nil, err
	}

	// Verify anonymous attestation (BBS+ proof)
	var issuerKeys []transport.IssuerKeyInfo
	if profile, profileErr := cfg.GetActiveProfile(); profileErr == nil {
		if len(profile.IssuerPublicKey) > 0 {
			issuerKeys = []transport.IssuerKeyInfo{{
				ID:        profile.IssuerPublicKeyID,
				PublicKey: profile.IssuerPublicKey,
			}}
		}
	}
	if err := transport.VerifyAttestationFromJSON(decrypted, requestIDString, issuerKeys, transport.SkipAttestationRequested()); err != nil {
		return nil, err
	}

	// Parse the response
	var response ApprovalResponse
	if err := json.Unmarshal(decrypted, &response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Check for errors
	if getErrorCode(&response) != nil {
		return &ApprovalResult{
			Approved: false,
			Message:  getErrorMessage(&response),
		}, nil
	}

	decision := getDecision(&response)

	// Handle deny decision
	if decision == "deny" {
		return &ApprovalResult{
			Approved: false,
			Message:  "Request was rejected by user",
		}, nil
	}

	// Verify signature for allow decisions
	if decision == "allow" || decision == "allow_always" {
		if len(response.ContextSignature) == 0 {
			return nil, ErrMissingSignature
		}

		// Get the device's P-256 attestation public key from config
		userAccount := cfg.UserAccount()
		if userAccount == nil || len(userAccount.Devices) == 0 {
			return nil, fmt.Errorf("no devices available in user account")
		}

		// Use the first device's attestation public key
		device := userAccount.Devices[0]
		log.Debug("verifySignature: device approverId=%s, attestationPublicKey len=%d, contextPreimage len=%d, signature len=%d",
			device.ApproverId, len(device.AttestationPublicKey), len(contextPreimage), len(response.ContextSignature))
		if len(device.AttestationPublicKey) != crypto.PublicKeySize {
			return nil, fmt.Errorf("invalid attestation public key length: %d (expected %d compressed)", len(device.AttestationPublicKey), crypto.PublicKeySize)
		}

		publicKey, err := parseP256CompressedPublicKey(device.AttestationPublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}

		log.Debug("verifySignature: publicKey X=%s, Y=%s",
			publicKey.X.Text(16)[:16], publicKey.Y.Text(16)[:16])

		// Compute SHA-256 of the preimage and verify signature against the digest
		contextDigest := sha256.Sum256(contextPreimage)
		if err := verifySignature(contextDigest[:], response.ContextSignature, publicKey); err != nil {
			return nil, fmt.Errorf("signature verification failed: %w", err)
		}
	}

	// Build result
	result := &ApprovalResult{
		Approved:     true,
		AlwaysAllow:  decision == "allow_always",
		UpdatedInput: getUpdatedInput(&response),
		Message:      "Approved via AckAgent iOS",
	}

	// Add rule info if "always allow" was selected
	if response.RememberRule != nil {
		result.RuleID = generateRuleID()
		result.RulePattern = getRulePattern(response.RememberRule)
	}

	return result, nil
}

// parseP256CompressedPublicKey parses a compressed P-256 public key (33 bytes: 0x02/0x03 || X).
func parseP256CompressedPublicKey(compressed []byte) (*ecdsa.PublicKey, error) {
	if len(compressed) != crypto.PublicKeySize {
		return nil, fmt.Errorf("invalid compressed public key length: %d (expected %d)", len(compressed), crypto.PublicKeySize)
	}

	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), compressed)
	if x == nil {
		return nil, fmt.Errorf("failed to decompress P-256 public key")
	}

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}, nil
}

// verifySignature verifies a P-256 ECDSA signature.
func verifySignature(hash, signature []byte, publicKey *ecdsa.PublicKey) error {
	// The signature should be in ASN.1 DER format or raw r||s format
	if len(signature) == 64 {
		// Raw r||s format
		r := new(big.Int).SetBytes(signature[:32])
		s := new(big.Int).SetBytes(signature[32:])
		if !ecdsa.Verify(publicKey, hash, r, s) {
			return ErrInvalidSignature
		}
		return nil
	}

	// Try ASN.1 DER format
	if !ecdsa.VerifyASN1(publicKey, hash, signature) {
		return ErrInvalidSignature
	}
	return nil
}

// generateRuleID generates a unique ID for an always-allow rule.
func generateRuleID() string {
	bytes, _ := crypto.GenerateRandomBytes(8)
	return fmt.Sprintf("%x", bytes)
}

// processQuestionResponse decrypts and processes the question response.
func processQuestionResponse(
	resp *transport.Response,
	ephemeralPrivate []byte,
	requestID []byte,
	requestIDString string,
	cfg *config.Config,
) (*QuestionResult, error) {
	// Decrypt response using shared helper
	decrypted, err := resp.Decrypt(ephemeralPrivate, requestID)
	if err != nil {
		return nil, err
	}

	// Verify anonymous attestation (BBS+ proof)
	var issuerKeys []transport.IssuerKeyInfo
	if profile, profileErr := cfg.GetActiveProfile(); profileErr == nil {
		if len(profile.IssuerPublicKey) > 0 {
			issuerKeys = []transport.IssuerKeyInfo{{
				ID:        profile.IssuerPublicKeyID,
				PublicKey: profile.IssuerPublicKey,
			}}
		}
	}
	if err := transport.VerifyAttestationFromJSON(decrypted, requestIDString, issuerKeys, transport.SkipAttestationRequested()); err != nil {
		return nil, err
	}

	// Parse the response
	var response QuestionResponse
	if err := json.Unmarshal(decrypted, &response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Check for errors (user declined or skipped)
	if getQuestionErrorCode(&response) != nil {
		return &QuestionResult{
			Answered: false,
			Message:  getQuestionErrorMessage(&response),
		}, nil
	}

	// Verify signature
	answersSignature := getAnswersSignature(&response)
	if len(answersSignature) == 0 {
		return nil, ErrMissingSignature
	}

	// Get the device's P-256 signing public key from config
	userAccount := cfg.UserAccount()
	if userAccount == nil || len(userAccount.Devices) == 0 {
		return nil, fmt.Errorf("no devices available in user account")
	}

	// Use the first device's attestation public key
	device := userAccount.Devices[0]
	if len(device.AttestationPublicKey) != crypto.PublicKeySize {
		return nil, fmt.Errorf("invalid attestation public key length: %d (expected %d compressed)", len(device.AttestationPublicKey), crypto.PublicKeySize)
	}

	publicKey, err := parseP256CompressedPublicKey(device.AttestationPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	// Compute SHA256 of AnswersBytes and verify signature
	answersBytes := getAnswersBytes(&response)
	answersHash := sha256.Sum256(answersBytes)
	if err := verifySignature(answersHash[:], answersSignature, publicKey); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// Parse the answers from AnswersBytes
	var answers map[string]string
	if err := json.Unmarshal(answersBytes, &answers); err != nil {
		return nil, fmt.Errorf("failed to parse answers: %w", err)
	}

	return &QuestionResult{
		Answered: true,
		Answers:  answers,
		Message:  "Answered via AckAgent iOS",
	}, nil
}
