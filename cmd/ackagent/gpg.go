package main

import (
	"fmt"

	"github.com/spf13/cobra"

	gpgcli "github.com/ackagent/cli/internal/gpg/cli"
	"github.com/ackagent/cli/internal/gpg/commands"
	"github.com/ackagent/cli/internal/shared/version"
)

// GPG flags - pflag handles -bsau KEY natively!
var (
	gpgDetach     bool
	gpgSign       bool
	gpgVerify     bool
	gpgArmor      bool
	gpgVerbose    bool
	gpgLocalUser  string
	gpgOutput     string
	gpgStatusFD   int
	gpgDecrypt    bool
	gpgEncrypt    bool
	gpgRecipients []string
	gpgListKeys   bool
	gpgExport     bool
	gpgGenKey     bool
	gpgName       string
	gpgEmail      string
	gpgAlgorithm  string
)

var gpgCmd = &cobra.Command{
	Use:   "gpg [file]",
	Short: "GPG-compatible signing using iOS Secure Enclave keys",
	Long: `GPG-compatible signing and decryption using iOS Keychain keys.

Key Generation:
  --generate-key        Generate a new GPG key on iOS device
  --name NAME           User name for key (with --generate-key)
  --email EMAIL         User email for key (with --generate-key)

Signing Options:
  -b, --detach-sign     Create detached signature
  -s, --sign            Sign data
  -a, --armor           Create ASCII armored output
  -u KEY                Use KEY for signing
  -o FILE               Write output to FILE
  --status-fd=N         Write status to file descriptor N

Verification Options:
  --verify              Verify a detached signature

Decryption Options:
  -d, --decrypt         Decrypt data
  -o FILE               Write output to FILE

Encryption Options:
  -e, --encrypt         Encrypt data
  -r, --recipient KEY   Encrypt for KEY (fingerprint, key ID, or label)
  -a, --armor           Create ASCII armored output
  -o FILE               Write output to FILE

Key Management:
  -k, --list-keys       List enrolled keys
  --export              Export public key

Examples:
  # Generate a GPG key
  ackagent gpg --generate-key --name "Alice" --email "alice@example.com"

  # Sign a file (git uses -bsau FINGERPRINT)
  echo "test" | ackagent gpg -bsau FINGERPRINT

  # Decrypt a message
  ackagent gpg --decrypt encrypted.gpg

  # Encrypt a message
  echo 'Hello' | ackagent gpg -e -r <FINGERPRINT> --armor

  # Verify a detached signature (used by git verify-commit)
  ackagent gpg --verify signature.asc signed-data`,
	Args:                  cobra.MaximumNArgs(2),
	DisableFlagsInUseLine: true,
	Run:                   runGPG,
}

func init() {
	f := gpgCmd.Flags()

	// Boolean flags (can be combined: -bsau KEY)
	f.BoolVarP(&gpgDetach, "detach-sign", "b", false, "Create detached signature")
	f.BoolVarP(&gpgSign, "sign", "s", false, "Sign data")
	f.BoolVarP(&gpgArmor, "armor", "a", false, "ASCII armored output")
	f.BoolVarP(&gpgVerbose, "verbose", "v", false, "Verbose output")

	// Value flags
	f.StringVarP(&gpgLocalUser, "local-user", "u", "", "Use KEY for signing")
	f.StringVarP(&gpgOutput, "output", "o", "", "Write output to FILE")
	f.IntVar(&gpgStatusFD, "status-fd", -1, "Write status to FD")

	// Mode flags
	f.BoolVar(&gpgVerify, "verify", false, "Verify a detached signature")
	f.BoolVarP(&gpgDecrypt, "decrypt", "d", false, "Decrypt data")
	f.BoolVarP(&gpgEncrypt, "encrypt", "e", false, "Encrypt data")
	f.StringSliceVarP(&gpgRecipients, "recipient", "r", nil, "Encrypt for KEY")
	f.BoolVarP(&gpgListKeys, "list-keys", "k", false, "List keys")
	f.BoolVar(&gpgExport, "export", false, "Export public key")
	f.BoolVar(&gpgGenKey, "generate-key", false, "Generate new key")

	// Key generation flags
	f.StringVar(&gpgName, "name", "", "User name for key")
	f.StringVar(&gpgEmail, "email", "", "User email for key")
	f.StringVarP(&gpgAlgorithm, "type", "t", "", "Key algorithm: 'ecdsa' (p256, hardware-backed optional) or 'ed25519' (software-only)")

	// Ignored GPG options for compatibility (don't show in help)
	f.Bool("no-tty", false, "")
	f.Bool("batch", false, "")
	f.Bool("yes", false, "")
	f.Bool("no-armor", false, "")
	f.String("keyid-format", "", "")
	f.String("digest-algo", "", "")
	f.String("default-key", "", "")
	f.String("homedir", "", "")
	f.String("keyring", "", "")
	f.MarkHidden("no-tty")
	f.MarkHidden("batch")
	f.MarkHidden("yes")
	f.MarkHidden("no-armor")
	f.MarkHidden("keyid-format")
	f.MarkHidden("digest-algo")
	f.MarkHidden("default-key")
	f.MarkHidden("homedir")
	f.MarkHidden("keyring")
}

func runGPG(cmd *cobra.Command, args []string) {
	// Build Args struct for compatibility with existing command implementations
	parsedArgs := &gpgcli.Args{
		Armor:      gpgArmor,
		StatusFD:   gpgStatusFD,
		OutputFile: gpgOutput,
		LocalUser:  gpgLocalUser,
		Verbose:    gpgVerbose,
		Name:       gpgName,
		Email:      gpgEmail,
		Algorithm:  gpgAlgorithm,
		Recipients: gpgRecipients,
	}

	// Set input file from positional arg
	if len(args) > 0 {
		parsedArgs.InputFile = args[0]
	}
	if len(args) > 1 {
		parsedArgs.DataFile = args[1]
	}

	// Determine mode from flags
	switch {
	case cmd.Flags().Changed("version"):
		showGPGVersion()
		return
	case gpgVerify:
		parsedArgs.Mode = gpgcli.ModeVerify
	case gpgGenKey:
		parsedArgs.Mode = gpgcli.ModeGenerateKey
	case gpgListKeys:
		parsedArgs.Mode = gpgcli.ModeListKeys
	case gpgExport:
		parsedArgs.Mode = gpgcli.ModeExportKey
	case gpgDecrypt:
		parsedArgs.Mode = gpgcli.ModeDecrypt
	case gpgEncrypt:
		parsedArgs.Mode = gpgcli.ModeEncrypt
	case gpgDetach:
		parsedArgs.Mode = gpgcli.ModeDetach
	default:
		parsedArgs.Mode = gpgcli.ModeSign
	}

	// Global 'profile' flag is automatically available via the package variable
	cfg := loadConfigWithProfile(profile)

	// Execute the appropriate command
	switch parsedArgs.Mode {
	case gpgcli.ModeVerify:
		commands.Verify(cfg, parsedArgs)
	case gpgcli.ModeGenerateKey:
		commands.GenerateKey(cfg, parsedArgs)
	case gpgcli.ModeListKeys:
		commands.ListKeys(cfg)
	case gpgcli.ModeExportKey:
		commands.ExportKey(cfg, parsedArgs)
	case gpgcli.ModeDecrypt:
		commands.Decrypt(cfg, parsedArgs)
	case gpgcli.ModeEncrypt:
		commands.Encrypt(cfg, parsedArgs)
	case gpgcli.ModeSign, gpgcli.ModeDetach:
		commands.Sign(cfg, parsedArgs)
	}
}

func showGPGVersion() {
	fmt.Printf("ackagent gpg %s\n", version.Version)
	fmt.Println("Compatible with GPG for Git commit signing")
	fmt.Println("Uses iOS Secure Enclave keys via AckAgent app")
}
