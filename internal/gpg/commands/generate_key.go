package commands

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ackagent/cli/internal/gpg/cli"
	protocol "github.com/ackagent/api/go/protocol"
	"github.com/ackagent/cli/internal/shared/config"
	"github.com/ackagent/cli/internal/shared/sysinfo"
	"github.com/ackagent/cli/internal/shared/transport"
	"github.com/ackagent/cli/internal/shared/util"
)

const keyPurposeGPG = "gpg"

// GenerateKey generates a new GPG key on the iOS device
func GenerateKey(cfg *config.Config, args *cli.Args) {
	if !cfg.IsLoggedIn() {
		fmt.Fprintln(os.Stderr, "Error: Not logged in. Please run 'ackagent login' first.")
		os.Exit(1)
	}

	// Get name and email from args or prompt
	name := args.Name
	email := args.Email

	if name == "" || email == "" {
		reader := bufio.NewReader(os.Stdin)

		if name == "" {
			fmt.Print("Name: ")
			name, _ = reader.ReadString('\n')
			name = strings.TrimSpace(name)
		}

		if email == "" {
			fmt.Print("Email: ")
			email, _ = reader.ReadString('\n')
			email = strings.TrimSpace(email)
		}
	}

	if name == "" || email == "" {
		fmt.Fprintln(os.Stderr, "Error: Name and email are required.")
		os.Exit(1)
	}

	// Get algorithm from args (default to ecdsa)
	algorithm := args.Algorithm
	if algorithm == "" {
		algorithm = config.AlgorithmP256
	}
	if algorithm != config.AlgorithmP256 && algorithm != config.AlgorithmEd25519 {
		fmt.Fprintf(os.Stderr, "Error: Invalid key type: %s (use 'ecdsa' or 'ed25519')\n", algorithm)
		os.Exit(1)
	}

	label := fmt.Sprintf("%s <%s>", name, email)

	// Check for label uniqueness among GPG keys
	if !cfg.IsLabelUnique(config.KeyPurposeGPG, label) {
		fmt.Fprintf(os.Stderr, "Error: GPG key for %q already exists. Use a different name/email combination.\n", label)
		os.Exit(1)
	}

	algorithmDisplay := "ECDSA P-256"
	if algorithm == config.AlgorithmEd25519 {
		algorithmDisplay = "Ed25519"
	}

	fmt.Fprintf(os.Stderr, "Generating %s GPG key on mobile device...\n", algorithmDisplay)
	fmt.Fprintf(os.Stderr, "User ID: %s\n", label)

	keyInfo, err := requestKeyGeneration(cfg, keyPurposeGPG, label, algorithm)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Store the key in config
	// Use algorithm from response if provided, otherwise use requested algorithm
	respAlgorithm := keyInfo.Algorithm
	if respAlgorithm == "" {
		respAlgorithm = algorithm
	}

	keyMetadata := config.KeyMetadata{
		IOSKeyID:              keyInfo.ID,
		Label:                 label,
		PublicKey:             keyInfo.PublicKey,
		Algorithm:             respAlgorithm,
		Purpose:               config.KeyPurposeGPG,
		CreatedAt:             time.Now(),
		KeyCreationTimestamp:  keyInfo.KeyCreationTimestamp,
		UserIDSignature:       keyInfo.UserIDSignature,
		SubkeySignature:       keyInfo.SubkeySignature,
		EncryptionPublicKey:   keyInfo.EncryptionPublicKey,
		EncryptionFingerprint: keyInfo.EncryptionFingerprint,
	}
	cfg.AddKey(keyMetadata)
	if err := cfg.Save(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to save config: %v\n", err)
	}

	// Compute GPG fingerprint for display
	gpgFP := GPGFingerprint(&keyMetadata)

	fmt.Println()
	fmt.Printf("GPG key generated successfully!\n")
	fmt.Printf("  Fingerprint: %s\n", gpgFP)
	fmt.Printf("  Algorithm:   %s\n", algorithmDisplay)
	fmt.Println()
	fmt.Println("Add to git config:")
	fmt.Printf("  git config --global user.signingkey %s\n", gpgFP)
	fmt.Printf("  git config --global commit.gpgsign true\n")
	fmt.Printf("  git config --global gpg.program \"ackagent gpg\"\n")
}

// KeyGenerationInfo contains the response from iOS key generation.
// JSON tags use camelCase to match the OpenAPI spec (protocol.EnrollResponse).
type KeyGenerationInfo struct {
	ID          string `json:"id"`
	Fingerprint string `json:"fingerprint"`
	PublicKey   []byte `json:"publicKey"`
	Algorithm   string `json:"algorithm,omitempty"` // p256 or ed25519

	// Signature data for OpenPGP export (created at key generation time)
	KeyCreationTimestamp int64  `json:"keyCreationTimestamp,omitempty"` // Unix timestamp used for fingerprint
	UserIDSignature      []byte `json:"userIdSignature,omitempty"`      // Self-certification signature (0x13)
	SubkeySignature      []byte `json:"subkeySignature,omitempty"`      // Subkey binding signature (0x18)

	// ECDH encryption subkey data (for GPG P-256 keys)
	EncryptionPublicKey   []byte `json:"encryptionPublicKey,omitempty"`   // ECDH P-256 public key (33 bytes compressed: 0x02/0x03 || X)
	EncryptionFingerprint string `json:"encryptionFingerprint,omitempty"` // 40-char hex fingerprint of ECDH subkey
}

// GPGKeyGenPayload is an alias for protocol.EnrollPayload which includes all
// GPG key generation fields (IncludeCertification, Purpose, Algorithm, Label, Display).
type GPGKeyGenPayload = protocol.EnrollPayload

// enrollResponseWrapper wraps protocol.EnrollResponse with helper methods.
type enrollResponseWrapper struct {
	protocol.EnrollResponse
}

func (r *enrollResponseWrapper) getIosKeyId() string {
	if r.IosKeyId == nil {
		return ""
	}
	return *r.IosKeyId
}

// getEffectiveKeyID returns the best available key identifier.
// Prefers IosKeyId (set by iOS), falls back to Id (UUID set by Android).
func (r *enrollResponseWrapper) getEffectiveKeyID() string {
	if r.IosKeyId != nil && *r.IosKeyId != "" {
		return *r.IosKeyId
	}
	if r.Id != nil && *r.Id != "" {
		return *r.Id
	}
	return ""
}

func (r *enrollResponseWrapper) getFingerprint() string {
	if r.Fingerprint == nil {
		return ""
	}
	return *r.Fingerprint
}

func (r *enrollResponseWrapper) getPublicKey() []byte {
	if r.PublicKeyHex == nil {
		return nil
	}
	key, _ := hex.DecodeString(*r.PublicKeyHex)
	return key
}

func (r *enrollResponseWrapper) getAlgorithm() string {
	if r.Algorithm == nil {
		return ""
	}
	return *r.Algorithm
}

func (r *enrollResponseWrapper) getErrorCode() *int {
	if r.ErrorCode == nil {
		return nil
	}
	code := int(*r.ErrorCode)
	return &code
}

func (r *enrollResponseWrapper) getErrorMessage() string {
	if r.ErrorMessage == nil {
		return ""
	}
	return *r.ErrorMessage
}

func (r *enrollResponseWrapper) getKeyCreationTimestamp() int64 {
	if r.KeyCreationTimestamp == nil {
		return 0
	}
	return *r.KeyCreationTimestamp
}

func (r *enrollResponseWrapper) getUserIdSignature() []byte {
	if r.UserIdSignature == nil {
		return nil
	}
	return *r.UserIdSignature
}

func (r *enrollResponseWrapper) getSubkeySignature() []byte {
	if r.SubkeySignature == nil {
		return nil
	}
	return *r.SubkeySignature
}

func (r *enrollResponseWrapper) getEncryptionPublicKey() []byte {
	if r.EncryptionPublicKeyHex == nil {
		return nil
	}
	key, _ := hex.DecodeString(*r.EncryptionPublicKeyHex)
	return key
}

func (r *enrollResponseWrapper) getEncryptionFingerprint() string {
	if r.EncryptionFingerprint == nil {
		return ""
	}
	return *r.EncryptionFingerprint
}

func requestKeyGeneration(cfg *config.Config, purpose, label, algorithm string) (*KeyGenerationInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), config.DefaultSigningTimeout)
	defer cancel()

	// Build display fields for GPG key generation
	algorithmDisplay := "ECDSA P-256"
	if algorithm == config.AlgorithmEd25519 {
		algorithmDisplay = "Ed25519"
	}

	processInfo := sysinfo.GetProcessInfo()
	fields := []protocol.DisplayField{
		{Label: "Purpose", Value: "GPG Signing"},
		{Label: "Algorithm", Value: algorithmDisplay},
		{Label: "User ID", Value: label},
	}

	icon := "key.fill"
	historyTitle := "GPG Key Generated"
	subtitle := label
	payload := &GPGKeyGenPayload{
		Type:                 protocol.Enroll,
		Purpose:              protocol.AckAgentCommonKeyPurpose(purpose),
		Label:                &label,
		Algorithm:            &algorithm,
		IncludeCertification: util.Ptr(true),
		SourceInfo:           processInfo.ToSourceInfo(),
		Display: &protocol.GenericDisplaySchema{
			Title:        "Generate GPG Key?",
			HistoryTitle: &historyTitle,
			Subtitle:     &subtitle,
			Icon:         &icon,
			Fields:       fields,
		},
	}

	fmt.Fprintf(os.Stderr, "Waiting for approval on iOS device...\n")
	decrypted, err := transport.SendAndDecryptEnrollment(ctx, cfg, payload, config.DefaultSigningTimeout)
	if err != nil {
		return nil, fmt.Errorf("waiting for response failed: %w", err)
	}

	parsed, err := transport.ParseEnrollResponse(decrypted)
	if err != nil {
		return nil, err
	}
	response := enrollResponseWrapper{EnrollResponse: *parsed}

	return &KeyGenerationInfo{
		ID:                    response.getEffectiveKeyID(),
		Fingerprint:           response.getFingerprint(),
		PublicKey:             response.getPublicKey(),
		Algorithm:             response.getAlgorithm(),
		KeyCreationTimestamp:  response.getKeyCreationTimestamp(),
		UserIDSignature:       response.getUserIdSignature(),
		SubkeySignature:       response.getSubkeySignature(),
		EncryptionPublicKey:   response.getEncryptionPublicKey(),
		EncryptionFingerprint: response.getEncryptionFingerprint(),
	}, nil
}
