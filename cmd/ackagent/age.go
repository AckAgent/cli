package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ackagent/cli/internal/age"
	"github.com/ackagent/cli/internal/shared/config"
)

var ageCmd = &cobra.Command{
	Use:   "age",
	Short: "Manage age encryption keys",
	Long: `Generate and manage age encryption keys stored on iOS.

The age key is an X25519 key stored in the iOS Keychain with iCloud sync.
It can be used with the standard 'age' CLI tool via the age-plugin-ackagent plugin.

Commands:
  keygen     Generate a new age key on iOS
  recipient  Print the age recipient (public key) for encryption
  identity   Print the age identity for decryption

Example workflow:
  # Generate key on iOS
  ackagent age keygen

  # Get recipient to share with others
  ackagent age recipient
  # -> age1ackagent1qv7x...

  # Encrypt a file (anyone can do this)
  age -r $(ackagent age recipient) -o secret.age secret.txt

  # Decrypt (requires iOS approval)
  age -d -i $(ackagent age identity) secret.age > secret.txt`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var ageKeygenLabel string

var ageKeygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate a new age key on iOS",
	Long: `Generate a new X25519 age key on your iOS device.

The key is stored in the iOS Keychain with iCloud Keychain sync,
making it available on all your iOS devices linked to the same iCloud account.

If an age key already exists, this command returns the existing key.`,
	Run: runAgeKeygen,
}

var ageRecipientCmd = &cobra.Command{
	Use:   "recipient",
	Short: "Print the age recipient(s) (public key)",
	Long: `Print the age recipient string(s) for your enrolled age key(s).

The recipient is a bech32-encoded X25519 public key that anyone can use
to encrypt files to you. Share this string with people who want to send
you encrypted files.

Example:
  age -r $(ackagent age recipient) -o secret.age secret.txt`,
	Run: runAgeRecipient,
}

var ageIdentitySave bool

var ageIdentityCmd = &cobra.Command{
	Use:   "identity",
	Short: "Print the age identity(ies) for decryption",
	Long: `Print the age identity string(s) for your enrolled age key(s).

The identity is a reference to your key that the age-plugin-ackagent
plugin uses to locate your key and request decryption approval from iOS.

This command outputs the identity string(s) directly, which can be used with
age's -i flag or saved to a file.

Example:
  # Use directly with process substitution
  age -d -i <(ackagent age identity) secret.age > secret.txt

  # Or save to a file first
  ackagent age identity > ~/.config/ackagent/age-identity.txt
  age -d -i ~/.config/ackagent/age-identity.txt secret.age > secret.txt`,
	Run: runAgeIdentity,
}

func init() {
	// keygen flags
	ageKeygenCmd.Flags().StringVarP(&ageKeygenLabel, "label", "l", "ackagent-age", "Label for the key")

	// identity flags
	ageIdentityCmd.Flags().BoolVarP(&ageIdentitySave, "save", "s", false, "Save identities to default file (~/.config/ackagent/age-identity.txt)")

	// Add subcommands
	ageCmd.AddCommand(ageKeygenCmd)
	ageCmd.AddCommand(ageRecipientCmd)
	ageCmd.AddCommand(ageIdentityCmd)
}

func runAgeKeygen(cmd *cobra.Command, args []string) {
	cfg := loadConfigWithProfile(profile)

	if !cfg.IsLoggedIn() {
		die("not logged in: run 'ackagent login' first")
	}

	// Check for label uniqueness among Age keys
	if !cfg.IsLabelUnique(config.KeyPurposeAge, ageKeygenLabel) {
		die("age key with label %q already exists. Use a different --label", ageKeygenLabel)
	}
	fmt.Fprintf(os.Stderr, "Generating age key on iOS...\n")

	keyMeta, err := age.EnrollAgeKey(cfg, ageKeygenLabel)
	if err != nil {
		die("failed to generate key: %v", err)
	}

	// Save key to config
	cfg.AddKey(*keyMeta)

	if err := cfg.Save(); err != nil {
		die("failed to save config: %v", err)
	}

	fmt.Fprintf(os.Stderr, "Age key generated successfully!\n\n")
	fmt.Fprintf(os.Stderr, "Recipient (share this for encryption):\n")
	fmt.Printf("%s\n", keyMeta.AgeRecipient)
}

func runAgeRecipient(cmd *cobra.Command, args []string) {
	cfg := loadConfigWithProfile(profile)

	if !cfg.IsLoggedIn() {
		die("not logged in: run 'ackagent login' first")
	}

	ageKeys := cfg.KeysForPurpose(config.KeyPurposeAge)
	if len(ageKeys) == 0 {
		die("no age key enrolled")
	}

	// Print all age recipients
	for _, key := range ageKeys {
		if key.AgeRecipient != "" {
			fmt.Println(key.AgeRecipient)
		} else {
			// Reconstruct from public key
			recipient := &age.Recipient{PublicKey: key.PublicKey}
			fmt.Println(recipient.String())
		}
	}
}

func runAgeIdentity(cmd *cobra.Command, args []string) {
	cfg := loadConfigWithProfile(profile)

	if !cfg.IsLoggedIn() {
		die("not logged in: run 'ackagent login' first")
	}

	if ageIdentitySave {
		path, err := age.WriteIdentityFile(cfg)
		if err != nil {
			die("failed to write identity file: %v", err)
		}
		fmt.Fprintf(os.Stderr, "Identities saved to: %s\n", path)
		return
	}

	ageKeys := cfg.KeysForPurpose(config.KeyPurposeAge)
	if len(ageKeys) == 0 {
		die("no age key enrolled")
	}

	// Print all age identities
	for _, key := range ageKeys {
		identity := &age.Identity{PublicKeyHex: key.Hex()}
		fmt.Println(identity.String())
	}
}
