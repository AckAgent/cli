package commands

import (
	"fmt"
	"os"
	"time"

	"github.com/ackagent/cli/internal/gpg/cli"
	"github.com/ackagent/cli/internal/gpg/openpgp"
	"github.com/ackagent/cli/internal/shared/config"
)

// ExportKey exports a public key with self-certification signature.
// The exported key can be imported into system GPG.
func ExportKey(cfg *config.Config, args *cli.Args) {
	key := FindKey(cfg, args.LocalUser, config.KeyPurposeGPG)
	if key == nil {
		fmt.Fprintf(os.Stderr, "ackagent gpg: key not found: %s\n", args.LocalUser)
		os.Exit(1)
	}

	// Determine the key creation time
	// Use KeyCreationTimestamp if available (for consistent fingerprint computation)
	// Otherwise fall back to CreatedAt
	var keyCreationTime time.Time
	if key.KeyCreationTimestamp > 0 {
		keyCreationTime = time.Unix(key.KeyCreationTimestamp, 0)
	} else {
		keyCreationTime = key.CreatedAt
	}

	// Build primary public key packet based on algorithm
	var pubKeyPacket []byte
	if key.IsEd25519() {
		pubKeyPacket = openpgp.BuildPublicKeyPacketEd25519(key.PublicKey, keyCreationTime)
	} else {
		pubKeyPacket = openpgp.BuildPublicKeyPacket(key.PublicKey, keyCreationTime)
	}
	userIDPacket := openpgp.BuildUserIDPacket(key.Label)

	// Start with primary key + user ID
	packets := append(pubKeyPacket, userIDPacket...)

	// Include self-certification signature if available
	// This is required for GPG to accept the key as valid
	if len(key.UserIDSignature) > 0 {
		if key.IsEd25519() {
			packets = append(packets, openpgp.FixEdDSASignatureMPIs(key.UserIDSignature)...)
		} else {
			packets = append(packets, key.UserIDSignature...)
		}
	} else if args.Verbose {
		fmt.Fprintf(os.Stderr, "ackagent gpg: note: key has no self-certification signature\n")
		fmt.Fprintf(os.Stderr, "  GPG may reject this key with 'no valid user IDs'\n")
		fmt.Fprintf(os.Stderr, "  Regenerate the key to create a properly signed export\n")
	}

	// If key has encryption subkey, include it with binding signature
	if key.HasEncryptionSubkey() {
		// Build subkey packet (Curve25519 for Ed25519 keys, P-256 for ECDSA keys)
		var subkeyPacket []byte
		if key.IsEd25519() {
			subkeyPacket = openpgp.BuildCurve25519SubkeyPacket(key.EncryptionPublicKey, keyCreationTime)
		} else {
			subkeyPacket = openpgp.BuildSubkeyPacket(key.EncryptionPublicKey, keyCreationTime)
		}
		packets = append(packets, subkeyPacket...)

		// Include subkey binding signature if available
		if len(key.SubkeySignature) > 0 {
			if key.IsEd25519() {
				packets = append(packets, openpgp.FixEdDSASignatureMPIs(key.SubkeySignature)...)
			} else {
				packets = append(packets, key.SubkeySignature...)
			}
		} else if args.Verbose {
			fmt.Fprintf(os.Stderr, "ackagent gpg: note: subkey has no binding signature\n")
			fmt.Fprintf(os.Stderr, "  Primary fingerprint: %s\n", GPGFingerprint(key))
			fmt.Fprintf(os.Stderr, "  Subkey fingerprint:  %s\n", key.EncryptionFingerprint)
		}
	}

	if args.Armor {
		fmt.Print(openpgp.Armor(openpgp.ArmorPublicKey, packets))
	} else {
		os.Stdout.Write(packets)
	}
}
