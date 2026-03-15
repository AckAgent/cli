package commands

import (
	"fmt"

	"github.com/ackagent/cli/internal/gpg/openpgp"
	"github.com/ackagent/cli/internal/shared/config"
)

// ListKeys lists all enrolled GPG keys
func ListKeys(cfg *config.Config) {
	// Filter to only GPG keys
	var gpgKeys []config.KeyMetadata
	for _, key := range cfg.Keys() {
		if key.Purpose == config.KeyPurposeGPG {
			gpgKeys = append(gpgKeys, key)
		}
	}

	if len(gpgKeys) == 0 {
		fmt.Println("No GPG keys.")
		fmt.Println("Use 'ackagent gpg --generate-key' to create one.")
		return
	}

	for _, key := range gpgKeys {
		// Compute GPG fingerprint from public key and creation timestamp
		gpgFP := GPGFingerprint(&key)
		if gpgFP == "" || len(gpgFP) != 40 {
			fmt.Printf("Warning: key %s has no valid GPG fingerprint, skipping\n", key.Label)
			continue
		}
		formattedFP := openpgp.FormatFingerprintHex(gpgFP)

		// Determine algorithm display string
		algoDisplay := "nistp256"
		if key.Algorithm == config.AlgorithmEd25519 {
			algoDisplay = "EdDSA"
		}

		fmt.Printf("sec   %s %s\n", algoDisplay, key.CreatedAt.Format("2006-01-02"))
		fmt.Printf("      %s\n", formattedFP)
		fmt.Printf("uid   %s\n", key.Label)
		fmt.Println()
	}
}
