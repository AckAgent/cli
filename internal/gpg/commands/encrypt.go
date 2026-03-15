package commands

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ackagent/cli/crypto"
	"github.com/ackagent/cli/internal/gpg/cli"
	gpgcrypto "github.com/ackagent/cli/internal/gpg/crypto"
	"github.com/ackagent/cli/internal/gpg/openpgp"
	"github.com/ackagent/cli/internal/shared/config"
)

// Encrypt encrypts data for one or more recipients.
// Encryption uses only public keys - no iOS device needed.
func Encrypt(cfg *config.Config, args *cli.Args) {
	if len(args.Recipients) == 0 {
		fmt.Fprintf(os.Stderr, "ackagent gpg: no recipients specified\n")
		fmt.Fprintf(os.Stderr, "Use -r/--recipient to specify recipients by fingerprint or email\n")
		os.Exit(1)
	}

	// Read input data (plaintext)
	var plaintext []byte
	var err error
	if args.InputFile != "" && args.InputFile != "-" {
		plaintext, err = os.ReadFile(args.InputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ackagent gpg: %v\n", err)
			os.Exit(1)
		}
	} else {
		plaintext, err = io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ackagent gpg: %v\n", err)
			os.Exit(1)
		}
	}

	// Resolve recipients to keys
	recipientKeys := resolveRecipients(cfg, args.Recipients)
	if len(recipientKeys) == 0 {
		fmt.Fprintf(os.Stderr, "ackagent gpg: no valid recipients found\n")
		os.Exit(1)
	}

	if args.Verbose {
		fmt.Fprintf(os.Stderr, "ackagent gpg: encrypting to %d recipient(s)\n", len(recipientKeys))
		for _, key := range recipientKeys {
			fmt.Fprintf(os.Stderr, "  - %s (%s)\n", key.Label, GPGFingerprint(key))
		}
	}

	// Generate random session key
	symAlgo := openpgp.SymAlgoAES256
	sessionKey, err := gpgcrypto.GenerateSessionKey(byte(symAlgo))
	if err != nil {
		fmt.Fprintf(os.Stderr, "ackagent gpg: failed to generate session key: %v\n", err)
		os.Exit(1)
	}

	// Build literal data packet containing the plaintext
	literalPacket := buildLiteralDataPacket(plaintext, args.InputFile)

	// Encrypt with session key (SEIPD v1 for compatibility)
	encryptedData, err := gpgcrypto.EncryptSEIPDv1(sessionKey, literalPacket, byte(symAlgo))
	if err != nil {
		fmt.Fprintf(os.Stderr, "ackagent gpg: encryption failed: %v\n", err)
		os.Exit(1)
	}

	// Build session key with algorithm and checksum for wrapping
	sessionKeyWithChecksum := gpgcrypto.BuildSessionKeyWithChecksum(byte(symAlgo), sessionKey)

	// Create PKESK packets for each recipient
	var pkeskPackets [][]byte
	for _, key := range recipientKeys {
		// Use encryption subkey if available, otherwise fall back to primary key
		encryptionPubKey := key.EffectiveEncryptionPublicKey()
		encryptionFingerprint := key.EffectiveEncryptionFingerprint()

		// Determine curve and validate key size based on algorithm
		var ecdhCurve gpgcrypto.ECDHCurve
		if key.IsEd25519() {
			if len(encryptionPubKey) != 32 {
				fmt.Fprintf(os.Stderr, "ackagent gpg: invalid Curve25519 public key for %s (expected 32 bytes, got %d)\n", key.Label, len(encryptionPubKey))
				os.Exit(1)
			}
			ecdhCurve = gpgcrypto.ECDHCurveCurve25519
		} else {
			if len(encryptionPubKey) != crypto.PublicKeySize {
				fmt.Fprintf(os.Stderr, "ackagent gpg: invalid public key for %s (expected %d bytes compressed, got %d)\n", key.Label, crypto.PublicKeySize, len(encryptionPubKey))
				os.Exit(1)
			}
			ecdhCurve = gpgcrypto.ECDHCurveP256
		}

		// Get fingerprint bytes for the encryption key (subkey if available)
		fingerprint := openpgp.ParseFingerprint(encryptionFingerprint)
		if fingerprint == nil {
			fmt.Fprintf(os.Stderr, "ackagent gpg: invalid fingerprint for %s\n", key.Label)
			os.Exit(1)
		}

		// ECDH key wrap
		params := &gpgcrypto.ECDHParams{
			HashAlgo:  openpgp.HashAlgoSHA256,
			SymAlgo:   openpgp.SymAlgoAES256,
			PublicKey: encryptionPubKey,
			Curve:     ecdhCurve,
		}

		ephemeralPoint, wrappedKey, err := gpgcrypto.WrapSessionKey(params, sessionKeyWithChecksum, fingerprint)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ackagent gpg: key wrap failed for %s: %v\n", key.Label, err)
			os.Exit(1)
		}

		// Extract key ID (last 8 bytes of encryption fingerprint)
		keyID := fingerprint[len(fingerprint)-8:]

		// Build PKESK packet (handles both P-256 65-byte and Curve25519 33-byte ephemeral points)
		pkeskBody, err := openpgp.BuildPKESK(keyID, ephemeralPoint, wrappedKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ackagent gpg: failed to build PKESK: %v\n", err)
			os.Exit(1)
		}

		// Wrap in packet format
		pkeskPacket := openpgp.BuildPacket(openpgp.PacketTagPKESK, pkeskBody)
		pkeskPackets = append(pkeskPackets, pkeskPacket)

		if args.Verbose && key.HasEncryptionSubkey() {
			fmt.Fprintf(os.Stderr, "  Using encryption subkey: %s\n", encryptionFingerprint)
		}
	}

	// Build SEIPD packet
	seipdPacket := openpgp.BuildPacket(openpgp.PacketTagSEIPD, encryptedData)

	// Combine packets: PKESK(s) || SEIPD
	var message []byte
	for _, pkesk := range pkeskPackets {
		message = append(message, pkesk...)
	}
	message = append(message, seipdPacket...)

	// Output - armor if requested
	var output io.Writer = os.Stdout
	if args.OutputFile != "" && args.OutputFile != "-" {
		f, err := os.Create(args.OutputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ackagent gpg: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		output = f
	}

	if args.Armor {
		armored := openpgp.Armor(openpgp.ArmorMessage, message)
		output.Write([]byte(armored))
	} else {
		output.Write(message)
	}
}

// resolveRecipients resolves recipient specifiers to KeyMetadata.
// Recipients can be specified by:
// - Fingerprint (full or partial)
// - Key ID (last 16 or 8 hex chars)
// - Label/email
func resolveRecipients(cfg *config.Config, recipients []string) []*config.KeyMetadata {
	keys := cfg.KeysForPurpose(config.KeyPurposeGPG)
	if len(keys) == 0 {
		fmt.Fprintf(os.Stderr, "ackagent gpg: no keys enrolled\n")
		return nil
	}

	var result []*config.KeyMetadata
	for _, recipient := range recipients {
		key := findKeyByRecipient(keys, recipient)
		if key != nil {
			result = append(result, key)
		} else {
			fmt.Fprintf(os.Stderr, "ackagent gpg: warning: recipient not found: %s\n", recipient)
		}
	}

	return result
}

// findKeyByRecipient finds a key by fingerprint, key ID, or label.
func findKeyByRecipient(keys []config.KeyMetadata, query string) *config.KeyMetadata {
	query = strings.ToUpper(strings.ReplaceAll(query, " ", ""))

	for i := range keys {
		fp := strings.ToUpper(GPGFingerprint(&keys[i]))

		// Match full fingerprint
		if fp == query {
			return &keys[i]
		}

		// Match last 16 hex chars (key ID)
		if len(fp) >= 16 && len(query) <= 16 && strings.HasSuffix(fp, query) {
			return &keys[i]
		}

		// Match last 8 hex chars (short key ID)
		if len(fp) >= 8 && len(query) <= 8 && strings.HasSuffix(fp, query) {
			return &keys[i]
		}

		// Match label (case-insensitive)
		if strings.EqualFold(keys[i].Label, strings.ToLower(query)) {
			return &keys[i]
		}
	}

	return nil
}

// buildLiteralDataPacket creates a literal data packet.
// RFC 4880 section 5.9
func buildLiteralDataPacket(data []byte, filename string) []byte {
	pw := openpgp.NewPacketWriter()

	// Format: binary (0x62 = 'b')
	pw.WriteByte('b')

	// Filename (or "_CONSOLE" for stdin)
	if filename == "" || filename == "-" {
		filename = "_CONSOLE"
	}
	if len(filename) > 255 {
		filename = filename[:255]
	}
	pw.WriteByte(byte(len(filename)))
	pw.Write([]byte(filename))

	// Date: use zero for privacy
	pw.WriteUint32(0)

	// Data
	pw.Write(data)

	body := pw.Bytes()
	return openpgp.BuildPacket(openpgp.PacketTagLiteralData, body)
}

// FormatFingerprint formats a fingerprint for display (with spaces).
func FormatFingerprint(fp []byte) string {
	hexStr := strings.ToUpper(hex.EncodeToString(fp))
	// Add spaces every 4 characters
	var parts []string
	for i := 0; i < len(hexStr); i += 4 {
		end := i + 4
		if end > len(hexStr) {
			end = len(hexStr)
		}
		parts = append(parts, hexStr[i:end])
	}
	return strings.Join(parts, " ")
}
