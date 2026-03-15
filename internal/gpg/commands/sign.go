package commands

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/ackagent/cli/internal/gpg/cli"
	"github.com/ackagent/cli/internal/gpg/openpgp"
	"github.com/ackagent/cli/internal/shared/config"
)

// Sign signs data using the iOS device.
// iOS builds the complete OpenPGP signature - this ensures users see and approve
// the actual data being signed, preventing a malicious CLI from tricking users.
func Sign(cfg *config.Config, args *cli.Args) {
	if !cfg.IsLoggedIn() {
		fmt.Fprintf(os.Stderr, "ackagent gpg: not logged in\n")
		fmt.Fprintf(os.Stderr, "Run 'ackagent login' to login first.\n")
		os.Exit(1)
	}

	// If no -u flag is provided and multiple GPG keys exist, error with list
	if args.LocalUser == "" {
		gpgKeys := cfg.KeysForPurpose(config.KeyPurposeGPG)
		if len(gpgKeys) > 1 {
			fmt.Fprintf(os.Stderr, "ackagent gpg: multiple GPG keys enrolled, use -u to select:\n\n")
			for _, k := range gpgKeys {
				fmt.Fprintf(os.Stderr, "  %s (%s)\n", GPGFingerprint(&k), k.Label)
			}
			fmt.Fprintf(os.Stderr, "\nExample: ackagent gpg -u %s ...\n", GPGFingerprint(&gpgKeys[0]))
			os.Exit(1)
		}
	}

	key := FindKey(cfg, args.LocalUser, config.KeyPurposeGPG)
	if key == nil {
		if args.LocalUser != "" {
			fmt.Fprintf(os.Stderr, "ackagent gpg: key not found: %s\n", args.LocalUser)
		} else {
			fmt.Fprintf(os.Stderr, "ackagent gpg: no keys enrolled\n")
			fmt.Fprintf(os.Stderr, "Enroll a key using the AckAgent iOS app first.\n")
		}
		os.Exit(1)
	}

	// Read input data
	var data []byte
	var err error
	if args.InputFile != "" && args.InputFile != "-" {
		data, err = os.ReadFile(args.InputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ackagent gpg: %v\n", err)
			os.Exit(1)
		}
	} else {
		data, err = io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ackagent gpg: %v\n", err)
			os.Exit(1)
		}
	}

	// Setup status writer
	status := cli.NewStatusWriter(args.StatusFD)
	defer status.Close()

	status.BeginSigning()

	// Extract action context from data (detect git commits, etc.)
	actionCtx := ExtractOperationContext(data, args)

	// Send raw data to iOS - iOS builds the complete OpenPGP signature
	// This ensures users see the actual data being signed, not just a hash
	armoredSignature, err := RequestGPGSignature(cfg, key, data, actionCtx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ackagent gpg: signing failed: %v\n", err)
		os.Exit(1)
	}

	// Write output - signature is already armored from iOS
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

	// iOS always returns armored signatures
	output.Write([]byte(armoredSignature))

	// Write status - use the key's fingerprint for GPG status output
	fingerprint := openpgp.ParseFingerprint(GPGFingerprint(key))

	// Determine public key algorithm based on key metadata
	pkAlgo := byte(openpgp.PubKeyAlgoECDSA)
	if key.IsEd25519() {
		pkAlgo = openpgp.PubKeyAlgoEdDSA
	}

	status.SigCreated('D', pkAlgo, openpgp.HashAlgoSHA256, 0x00,
		time.Now().Unix(), openpgp.FormatFingerprint(fingerprint))
}
