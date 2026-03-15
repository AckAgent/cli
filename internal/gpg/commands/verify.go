package commands

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ackagent/cli/internal/gpg/cli"
	"github.com/ackagent/cli/internal/gpg/openpgp"
	"github.com/ackagent/cli/internal/shared/config"
)

// Verify verifies a detached GPG signature.
// This is invoked when git calls: gpg.program --status-fd=1 --verify <sig-file> <data-file>
func Verify(cfg *config.Config, args *cli.Args) {
	if !cfg.IsLoggedIn() {
		fmt.Fprintf(os.Stderr, "ackagent gpg: not logged in\n")
		fmt.Fprintf(os.Stderr, "Run 'ackagent login' to login first.\n")
		os.Exit(1)
	}

	// Read signature file
	if args.InputFile == "" {
		fmt.Fprintf(os.Stderr, "ackagent gpg: --verify requires a signature file\n")
		os.Exit(1)
	}

	sigData, err := os.ReadFile(args.InputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ackagent gpg: failed to read signature file: %v\n", err)
		os.Exit(1)
	}

	// Read signed data from DataFile or stdin
	var data []byte
	if args.DataFile == "" || args.DataFile == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(args.DataFile)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "ackagent gpg: failed to read signed data: %v\n", err)
		os.Exit(1)
	}

	// Setup status writer
	status := cli.NewStatusWriter(args.StatusFD)
	defer status.Close()

	// Dearmor signature if needed
	sigBinary, _, err := openpgp.Dearmor(sigData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ackagent gpg: failed to decode signature: %v\n", err)
		os.Exit(1)
	}

	// Parse packets and find signature packet (tag 2)
	packets, err := openpgp.ParseAllPackets(sigBinary)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ackagent gpg: failed to parse signature packets: %v\n", err)
		os.Exit(1)
	}

	var sigPacket *openpgp.ParsedSignature
	for _, pkt := range packets {
		if pkt.Tag == openpgp.PacketTagSignature {
			sigPacket, err = openpgp.ParseSignaturePacket(pkt.Body)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ackagent gpg: failed to parse signature: %v\n", err)
				os.Exit(1)
			}
			break
		}
	}

	if sigPacket == nil {
		fmt.Fprintf(os.Stderr, "ackagent gpg: no signature packet found\n")
		os.Exit(1)
	}

	// Build a key ID string for lookup
	keyIDStr := issuerKeyIDString(sigPacket)

	// Find matching key in config by fingerprint or key ID
	key := FindKey(cfg, keyIDStr, config.KeyPurposeGPG)
	if key == nil && sigPacket.IssuerKeyID != 0 {
		// Try the 16-char key ID from issuer subpacket
		key = FindKey(cfg, openpgp.FormatKeyID(sigPacket.IssuerKeyID), config.KeyPurposeGPG)
	}

	if key == nil {
		status.NoPublicKey(keyIDStr)
		fmt.Fprintf(os.Stderr, "ackagent gpg: public key %s not found\n", keyIDStr)
		os.Exit(2)
	}

	fingerprint := GPGFingerprint(key)
	keyIDLong := keyIDStr
	if len(fingerprint) >= 16 {
		keyIDLong = fingerprint[len(fingerprint)-16:]
	}
	userID := key.Label

	// Verify the signature cryptographically
	err = openpgp.VerifyDetached(key.PublicKey, key.IsEd25519(), data, sigPacket)
	if err != nil {
		status.BadSig(keyIDLong, userID)
		fmt.Fprintf(os.Stderr, "ackagent gpg: BAD signature from \"%s\"\n", userID)
		os.Exit(1)
	}

	// Success - write status lines that git expects
	status.NewSig()
	status.GoodSig(keyIDLong, userID)
	status.ValidSig(fingerprint, int64(sigPacket.CreationTime), sigPacket.PubKeyAlgo, sigPacket.HashAlgo)
	status.TrustUltimate()

	fmt.Fprintf(os.Stderr, "ackagent gpg: Good signature from \"%s\"\n", userID)
	fmt.Fprintf(os.Stderr, "ackagent gpg: using key %s\n", openpgp.FormatFingerprintHex(fingerprint))

	// Explicitly exit with 0. The defer status.Close() would close the status fd
	// (possibly fd 1 = stdout), which can cause Go runtime cleanup issues.
	// os.Exit skips defers; the OS closes all fds on process exit.
	os.Exit(0)
}

// issuerKeyIDString returns a hex key ID string from the signature for key lookup.
func issuerKeyIDString(sig *openpgp.ParsedSignature) string {
	if sig.IssuerFP != nil {
		return strings.ToUpper(hex.EncodeToString(sig.IssuerFP))
	}
	if sig.IssuerKeyID != 0 {
		return openpgp.FormatKeyID(sig.IssuerKeyID)
	}
	return ""
}
