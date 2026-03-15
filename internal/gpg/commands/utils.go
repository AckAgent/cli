package commands

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ackagent/cli/internal/gpg/openpgp"
	protocol "github.com/ackagent/api/go/protocol"
	"github.com/ackagent/cli/internal/shared/client"
	"github.com/ackagent/cli/internal/shared/config"
	"github.com/ackagent/cli/internal/shared/sysinfo"
	"github.com/ackagent/cli/internal/shared/transport"
	"github.com/ackagent/cli/internal/shared/util"
)

// GPGFingerprint computes the GPG V4 fingerprint (40-char hex) from a key's metadata.
// For GPG keys, the V4 fingerprint is computed from the raw public key and creation timestamp.
// Returns empty string if the key is not a GPG key or computation fails.
func GPGFingerprint(key *config.KeyMetadata) string {
	if key.Purpose != config.KeyPurposeGPG {
		return ""
	}
	if len(key.PublicKey) == 0 {
		return ""
	}
	var creationTime time.Time
	if key.KeyCreationTimestamp > 0 {
		creationTime = time.Unix(key.KeyCreationTimestamp, 0)
	} else {
		creationTime = key.CreatedAt
	}
	var fp []byte
	if key.IsEd25519() {
		fp = openpgp.V4FingerprintEd25519(key.PublicKey, creationTime)
	} else {
		fp = openpgp.V4Fingerprint(key.PublicKey, creationTime)
	}
	return strings.ToUpper(hex.EncodeToString(fp))
}

// FindKey finds a key in the configuration by ID or label, filtered by purpose.
func FindKey(cfg *config.Config, keyID string, purpose config.KeyPurpose) *config.KeyMetadata {
	keys := cfg.KeysForPurpose(purpose)
	if len(keys) == 0 {
		return nil
	}

	if keyID == "" {
		// Return first key as default
		return &keys[0]
	}

	keyID = strings.ToUpper(strings.ReplaceAll(keyID, " ", ""))

	for i := range keys {
		gpgFP := strings.ToUpper(GPGFingerprint(&keys[i]))

		// Match full GPG fingerprint
		if gpgFP == keyID {
			return &keys[i]
		}

		// Match last 16 hex chars (key ID)
		if len(gpgFP) >= 16 && len(keyID) <= 16 && strings.HasSuffix(gpgFP, keyID) {
			return &keys[i]
		}

		// Match last 8 hex chars (short key ID)
		if len(gpgFP) >= 8 && len(keyID) <= 8 && strings.HasSuffix(gpgFP, keyID) {
			return &keys[i]
		}

		// Match label
		if strings.EqualFold(keys[i].Label, keyID) {
			return &keys[i]
		}
	}

	return nil
}

// ActionContext provides action-oriented metadata for the iOS approval UI
type ActionContext struct {
	Title            string               // e.g., "Sign commit?"
	Description      string               // e.g., first line of commit message
	OperationContext *GPGOperationContext // Full operation context (git or general)
}

// RequestGPGSignature sends raw data to iOS for GPG signing.
// iOS builds the complete OpenPGP signature and returns it armored.
// This ensures users see and approve the actual data being signed.
func RequestGPGSignature(cfg *config.Config, key *config.KeyMetadata, rawData []byte, actionCtx *ActionContext) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), config.DefaultSigningTimeout)
	defer cancel()

	// Collect process and system information
	processInfo := sysinfo.GetProcessInfo()

	// Build display fields starting with key info
	signatureIcon := "signature"
	fields := []protocol.DisplayField{
		{Label: "Key", Value: key.Label, Icon: &signatureIcon},
		{Label: "Fingerprint", Value: GPGFingerprint(key), Monospace: util.Ptr(true)},
	}

	// Determine title and subtitle based on action context
	title := "Sign data?"
	var subtitle *string
	historyTitle := "GPG Signature"

	if actionCtx != nil {
		if actionCtx.Title != "" {
			title = actionCtx.Title
		}
		if actionCtx.Description != "" {
			subtitle = &actionCtx.Description
		}

		// Add operation-specific display fields
		if actionCtx.OperationContext != nil {
			if actionCtx.OperationContext.IsGitCommit && actionCtx.OperationContext.GitContext != nil {
				git := actionCtx.OperationContext.GitContext
				historyTitle = "Git Commit Signed"
				fields = append(fields,
					protocol.DisplayField{Label: "Commit Message", Value: git.Message, Multiline: util.Ptr(true)},
					protocol.DisplayField{Label: "Author", Value: fmt.Sprintf("%s <%s>", git.AuthorName, git.AuthorEmail)},
				)
				if git.Branch != "" {
					fields = append(fields, protocol.DisplayField{Label: "Branch", Value: git.Branch, Monospace: util.Ptr(true)})
				}
				if git.RepoName != "" {
					fields = append(fields, protocol.DisplayField{Label: "Repository", Value: git.RepoName})
				}
			} else if actionCtx.OperationContext.GeneralContext != nil {
				gen := actionCtx.OperationContext.GeneralContext
				fields = append(fields,
					protocol.DisplayField{Label: "Operation", Value: gen.OperationType},
					protocol.DisplayField{Label: "Input", Value: gen.InputSource},
					protocol.DisplayField{Label: "Size", Value: fmt.Sprintf("%d bytes", gen.ContentSize)},
				)
				if gen.ContentPreview != "" {
					fields = append(fields, protocol.DisplayField{Label: "Content Preview", Value: gen.ContentPreview, Monospace: util.Ptr(true), Multiline: util.Ptr(true)})
				}
			}
		}
	}

	// Build GPG sign payload using generated type with GenericDisplaySchema
	icon := "signature"
	display := &protocol.GenericDisplaySchema{
		Title:        title,
		HistoryTitle: &historyTitle,
		Subtitle:     subtitle,
		Icon:         &icon,
		Fields:       fields,
	}

	payload := protocol.GpgSignPayload{
		Type:       protocol.GpgSign,
		Display:    display,
		RawData:    rawData,
		SourceInfo: processInfo.ToSourceInfo(),
	}

	fmt.Fprintf(os.Stderr, "Waiting for approval on iOS device...\n")

	// Send request using builder (handles encryption, submission, polling)
	decrypted, err := transport.NewRequestBuilder(cfg).
		WithKey(key.IOSKeyID, key.Hex()).
		SendAndDecrypt(ctx, payload)
	if err != nil {
		return "", err
	}

	// Parse the JSON response
	var gpgResponse client.GPGSignResponse
	if err := json.Unmarshal(decrypted, &gpgResponse); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if !gpgResponse.IsSuccess() {
		return "", gpgResponse.Error()
	}

	return gpgResponse.GetArmoredSignature(), nil
}

// GPGDecryptContext provides context for the decryption approval UI.
type GPGDecryptContext struct {
	SenderKeyID string // Key ID of the sender (if signed)
	EncryptedTo string // Email/user ID this was encrypted to
	MessageSize int    // Size of the encrypted message
	IsAnonymous bool   // Whether the recipient key ID is hidden (wildcard)
}

// RequestGPGDecrypt sends PKESK data to iOS for session key unwrapping.
// iOS performs ECDH key agreement and returns the unwrapped session key.
// The CLI then uses this session key to decrypt the SEIPD data locally.
func RequestGPGDecrypt(cfg *config.Config, key *config.KeyMetadata, pkesk *protocol.PkeskData, decryptCtx *GPGDecryptContext) (*client.GPGDecryptResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), config.DefaultSigningTimeout)
	defer cancel()

	// Collect process and system information
	processInfo := sysinfo.GetProcessInfo()

	// Build display fields for GPG decryption
	lockIcon := "lock.open"
	fields := []protocol.DisplayField{
		{Label: "Key", Value: key.Label, Icon: &lockIcon},
		{Label: "Fingerprint", Value: GPGFingerprint(key), Monospace: util.Ptr(true)},
	}

	// Add decryption context fields
	if decryptCtx != nil {
		if decryptCtx.SenderKeyID != "" {
			fields = append(fields, protocol.DisplayField{Label: "Sender Key ID", Value: decryptCtx.SenderKeyID, Monospace: util.Ptr(true)})
		}
		if decryptCtx.EncryptedTo != "" {
			fields = append(fields, protocol.DisplayField{Label: "Encrypted To", Value: decryptCtx.EncryptedTo})
		}
		if decryptCtx.MessageSize > 0 {
			fields = append(fields, protocol.DisplayField{Label: "Message Size", Value: fmt.Sprintf("%d bytes", decryptCtx.MessageSize)})
		}
	}

	// Build GPG decrypt payload using generated type with GenericDisplaySchema
	icon := "lock.open"
	historyTitle := "GPG Decryption"
	display := &protocol.GenericDisplaySchema{
		Title:        "Decrypt message?",
		HistoryTitle: &historyTitle,
		Icon:         &icon,
		Fields:       fields,
	}

	payload := protocol.GpgDecryptPayload{
		Type:          protocol.GpgDecrypt,
		Display:       display,
		EncryptedData: []byte{}, // Not used for PKESK-based decryption; iOS unwraps session key from PKESK
		Pkesk:         pkesk,
		SourceInfo:    processInfo.ToSourceInfo(),
	}

	fmt.Fprintf(os.Stderr, "Waiting for approval on iOS device...\n")

	// Send request using builder (handles encryption, submission, polling)
	decrypted, err := transport.NewRequestBuilder(cfg).
		WithKey(key.IOSKeyID, key.Hex()).
		SendAndDecrypt(ctx, payload)
	if err != nil {
		return nil, err
	}

	// Parse the JSON response
	var gpgResponse client.GPGDecryptResponse
	if err := json.Unmarshal(decrypted, &gpgResponse); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if !gpgResponse.IsSuccess() {
		return nil, gpgResponse.Error()
	}

	return &gpgResponse, nil
}
