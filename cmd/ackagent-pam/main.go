// ackagent-pam is a standalone CLI for PAM authentication testing and administration.
//
// This tool provides commands for:
// - Generating P-256 signing key pairs for PAM authentication
// - Exporting public keys for registration
// - Computing key fingerprints
// - Testing PAM authentication flows
//
// This is separate from the PAM module (.so) which integrates with the PAM stack.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ackagent/cli/internal/pam"
	"github.com/spf13/cobra"
)

var version = "dev"

func main() {
	rootCmd := &cobra.Command{
		Use:     "ackagent-pam",
		Short:   "AckAgent PAM authentication CLI",
		Version: version,
	}

	rootCmd.AddCommand(keygenCmd())
	rootCmd.AddCommand(exportPublicCmd())
	rootCmd.AddCommand(fingerprintCmd())
	rootCmd.AddCommand(testCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func keygenCmd() *cobra.Command {
	var orgID string
	var outputDir string
	var keyName string

	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate a new PAM signing key pair",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Generate P-256 key pair
			privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return fmt.Errorf("failed to generate key: %w", err)
			}

			// Marshal private key to PKCS8
			pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
			if err != nil {
				return fmt.Errorf("failed to marshal private key: %w", err)
			}

			// Create PEM block
			pemBlock := &pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: pkcs8Bytes,
			}

			// Ensure output directory exists
			if err := os.MkdirAll(outputDir, 0700); err != nil {
				return fmt.Errorf("failed to create output directory: %w", err)
			}

			// Write private key
			privateKeyPath := filepath.Join(outputDir, "org.key")
			privateKeyFile, err := os.OpenFile(privateKeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
			if err != nil {
				return fmt.Errorf("failed to create private key file: %w", err)
			}
			defer privateKeyFile.Close()

			if err := pem.Encode(privateKeyFile, pemBlock); err != nil {
				return fmt.Errorf("failed to write private key: %w", err)
			}

			// Compute public key hex
			rawPubKey := make([]byte, 64)
			privateKey.PublicKey.X.FillBytes(rawPubKey[:32])
			privateKey.PublicKey.Y.FillBytes(rawPubKey[32:])
			pubKeyHex := hex.EncodeToString(rawPubKey)

			fmt.Printf("Generated PAM key pair for organization: %s\n", orgID)
			fmt.Printf("Key name: %s\n", keyName)
			fmt.Printf("Private key: %s\n", privateKeyPath)
			fmt.Printf("Public Key: %s\n", pubKeyHex)

			return nil
		},
	}

	cmd.Flags().StringVar(&orgID, "org", "", "Organization ID")
	cmd.Flags().StringVar(&outputDir, "output", ".", "Output directory for key files")
	cmd.Flags().StringVar(&keyName, "name", "PAM Key", "Human-readable key name")
	cmd.MarkFlagRequired("org")

	return cmd
}

func exportPublicCmd() *cobra.Command {
	var keyPath string
	var format string

	cmd := &cobra.Command{
		Use:   "export-public",
		Short: "Export the public key from a private key file",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Load private key (unsafe: user-provided path, no /etc/ackagent restriction)
			signingKey, err := pam.LoadSigningKeyUnsafe(keyPath)
			if err != nil {
				return fmt.Errorf("failed to load key: %w", err)
			}

			// Get public key in DER format
			pubKeyDER, err := signingKey.PublicKeyDER()
			if err != nil {
				return fmt.Errorf("failed to marshal public key: %w", err)
			}

			switch format {
			case "base64":
				fmt.Println(base64.StdEncoding.EncodeToString(pubKeyDER))
			case "pem":
				pemBlock := &pem.Block{
					Type:  "PUBLIC KEY",
					Bytes: pubKeyDER,
				}
				pem.Encode(os.Stdout, pemBlock)
			default:
				return fmt.Errorf("unknown format: %s (use 'base64' or 'pem')", format)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&keyPath, "key", "", "Path to private key file")
	cmd.Flags().StringVar(&format, "format", "base64", "Output format (base64 or pem)")
	cmd.MarkFlagRequired("key")

	return cmd
}

func fingerprintCmd() *cobra.Command {
	var keyPath string

	cmd := &cobra.Command{
		Use:   "fingerprint",
		Short: "Display the fingerprint of a key",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Load private key (unsafe: user-provided path, no /etc/ackagent restriction)
			signingKey, err := pam.LoadSigningKeyUnsafe(keyPath)
			if err != nil {
				return fmt.Errorf("failed to load key: %w", err)
			}

			fmt.Println(signingKey.PublicKeyHex())
			return nil
		},
	}

	cmd.Flags().StringVar(&keyPath, "key", "", "Path to private key file")
	cmd.MarkFlagRequired("key")

	return cmd
}

func testCmd() *cobra.Command {
	var user string
	var service string
	var configPath string

	cmd := &cobra.Command{
		Use:   "test",
		Short: "Test PAM authentication for a user",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Load configuration (unsafe: user-provided path, no /etc/ackagent restriction)
			config, err := pam.LoadConfigUnsafe(configPath)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			fmt.Printf("Testing PAM authentication:\n")
			fmt.Printf("  User: %s\n", user)
			fmt.Printf("  Service: %s\n", service)
			fmt.Printf("  Config: %s\n", configPath)
			fmt.Printf("  Org: %s\n", config.Organization.ID)
			fmt.Printf("  Service Account: %s\n", config.Organization.ServiceAccountID)

			// Gather authentication context
			pamEnv := &pam.PAMEnv{
				RemoteHost: "127.0.0.1",
				TTY:        "pts/0",
			}
			authCtx := pam.GatherContext(user, service, pamEnv)

			fmt.Printf("  Context: service=%s, user=%s\n", authCtx.PAMService, authCtx.LocalUsername)

			// Create push authenticator
			authenticator, err := pam.NewPushAuthenticator(config)
			if err != nil {
				return fmt.Errorf("failed to create authenticator: %w", err)
			}

			// Set a timeout context
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(config.Auth.Timeout)*time.Second)
			defer cancel()

			fmt.Printf("\nSending PAM auth request...\n")

			// Authenticate
			result, err := authenticator.AuthenticateWithContext(ctx, authCtx)
			if err != nil {
				fmt.Printf("Authentication ERROR: %v\n", err)
				return err
			}

			if result.Approved {
				fmt.Printf("Authentication APPROVED by device %s\n", result.ApproverId)
				return nil
			}

			fmt.Printf("Authentication REJECTED or TIMEOUT\n")
			return fmt.Errorf("authentication not approved")
		},
	}

	cmd.Flags().StringVar(&user, "user", "", "Local username to authenticate")
	cmd.Flags().StringVar(&service, "service", "pam-test", "PAM service name")
	cmd.Flags().StringVar(&configPath, "config", "/etc/ackagent/pam.conf", "Path to config file")
	cmd.MarkFlagRequired("user")

	return cmd
}
