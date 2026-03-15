// Package display provides utilities for formatted output of CLI data.
package display

import (
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ackagent/cli/internal/gpg/openpgp"
	"github.com/ackagent/cli/internal/shared/config"
	"github.com/ackagent/cli/internal/ssh"
)

// PrintEnrolledKeys prints the list of enrolled keys to the given writer.
// Returns the number of keys printed.
func PrintEnrolledKeys(w io.Writer, keys []config.KeyMetadata) int {
	if len(keys) == 0 {
		fmt.Fprintln(w, "No enrolled keys.")
		return 0
	}

	fmt.Fprintln(w, "Enrolled Keys:")
	for i, key := range keys {
		fmt.Fprintf(w, "  %d. %s\n", i+1, key.Label)
		keyHex := key.Hex()
		fmt.Fprintf(w, "     Public Key: %s\n", keyHex)

		// Display protocol-specific fingerprint for readability
		switch key.Purpose {
		case config.KeyPurposeSSH:
			if sshFP := computeSSHFingerprint(key); sshFP != "" {
				fmt.Fprintf(w, "     SSH Fingerprint: %s\n", sshFP)
			}
		case config.KeyPurposeGPG:
			if gpgFP := computeGPGFingerprint(key); gpgFP != "" {
				fmt.Fprintf(w, "     GPG Fingerprint: %s\n", gpgFP)
			}
		case config.KeyPurposeAge:
			// For age keys, show truncated hex for readability
			if len(keyHex) > 16 {
				fmt.Fprintf(w, "     Age Key: %s...\n", keyHex[:16])
			}
		}

		fmt.Fprintf(w, "     Algorithm: %s\n", key.Algorithm)
		fmt.Fprintf(w, "     Created: %s\n", key.CreatedAt.Format(time.RFC3339))
		fmt.Fprintf(w, "     iOS Key ID: %s\n", key.IOSKeyID)
	}

	return len(keys)
}

// computeGPGFingerprint computes the GPG V4 fingerprint (40-char uppercase hex) from a key.
// Returns empty string if the key cannot produce a GPG fingerprint.
func computeGPGFingerprint(key config.KeyMetadata) string {
	if len(key.PublicKey) == 0 {
		return ""
	}

	// Use KeyCreationTimestamp for deterministic fingerprint if available, otherwise CreatedAt
	creationTime := key.CreatedAt
	if key.KeyCreationTimestamp > 0 {
		creationTime = time.Unix(key.KeyCreationTimestamp, 0)
	}

	var fp []byte
	switch {
	case strings.Contains(key.Algorithm, "ed25519") || strings.Contains(key.Algorithm, "Ed25519"):
		fp = openpgp.V4FingerprintEd25519(key.PublicKey, creationTime)
	case len(key.PublicKey) == 33 && (key.PublicKey[0] == 0x02 || key.PublicKey[0] == 0x03): // P-256 compressed (0x02/0x03 || X)
		fp = openpgp.V4Fingerprint(key.PublicKey, creationTime)
	default:
		return ""
	}

	return strings.ToUpper(hex.EncodeToString(fp))
}

// computeSSHFingerprint computes an SSH fingerprint (SHA256:base64) from the raw public key.
// Returns empty string if the key cannot be converted to an SSH fingerprint.
func computeSSHFingerprint(key config.KeyMetadata) string {
	if len(key.PublicKey) == 0 {
		return ""
	}

	// Decode hex public key if raw bytes are not available
	pubKey := key.PublicKey
	if len(pubKey) == 0 {
		keyHex := key.Hex()
		var err error
		pubKey, err = hex.DecodeString(keyHex)
		if err != nil {
			return ""
		}
	}

	return ssh.ComputeSSHFingerprint(pubKey, key.Algorithm)
}
