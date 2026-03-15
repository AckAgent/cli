package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ackagent/cli/internal/shared/config"
	"github.com/ackagent/cli/internal/ssh"
)

var (
	sshGenerateKey bool
	sshListKeys    bool
	sshKeyQuery    string
	sshOutput      string
	sshName        string
	sshType        string
)

var sshCmd = &cobra.Command{
	Use:   "ssh",
	Short: "Manage SSH keys backed by iOS Secure Enclave",
	Long: `Generate and manage SSH keys stored on iOS.

SSH keys can be ECDSA P-256 (default) or Ed25519. ECDSA keys can use Secure Enclave
for hardware-backed security. Ed25519 keys use software-only storage.

Operations:
  --generate-key  Generate a new SSH key on iOS and write key files
  --list-keys     List enrolled SSH keys
  --key <query>   Export an existing key to files

Example workflow:
  # Generate a new ECDSA P-256 SSH key (default, hardware-backed optional)
  ackagent ssh --generate-key -n mykey -o ~/.ssh/id_ackagent

  # Generate an Ed25519 SSH key (software-only)
  ackagent ssh --generate-key -n mykey-ed25519 -t ed25519 -o ~/.ssh/id_ackagent_ed25519

  # List enrolled keys
  ackagent ssh --list-keys

  # Export existing key to different path
  ackagent ssh --key mykey -o ~/.ssh/id_ackagent_backup

  # Use the key with SSH
  ssh -i ~/.ssh/id_ackagent user@host`,
	Run: runSSH,
}

func init() {
	f := sshCmd.Flags()
	f.BoolVarP(&sshGenerateKey, "generate-key", "g", false, "Generate a new SSH key on iOS")
	f.BoolVarP(&sshListKeys, "list-keys", "l", false, "List enrolled SSH keys")
	f.StringVarP(&sshKeyQuery, "key", "k", "", "Export existing key by name or fingerprint")
	f.StringVarP(&sshOutput, "output", "o", "", "Output path for key files (without extension)")
	f.StringVarP(&sshName, "name", "n", "", "Key label for iOS")
	f.StringVarP(&sshType, "type", "t", config.AlgorithmP256, "Key algorithm: 'ecdsa' (p256, hardware-backed optional) or 'ed25519' (software-only)")
}

func runSSH(cmd *cobra.Command, args []string) {
	cfg := loadConfigWithProfile(profile)

	// Ensure exactly one operation is specified
	opCount := 0
	if sshGenerateKey {
		opCount++
	}
	if sshListKeys {
		opCount++
	}
	if sshKeyQuery != "" {
		opCount++
	}

	if opCount == 0 {
		cmd.Help()
		return
	}
	if opCount > 1 {
		die("specify only one of --generate-key, --list-keys, or --key")
	}

	switch {
	case sshGenerateKey:
		runSSHGenerateKey(cfg)
	case sshListKeys:
		runSSHListKeys(cfg)
	case sshKeyQuery != "":
		runSSHExportKey(cfg)
	}
}

func runSSHGenerateKey(cfg *config.Config) {
	if !cfg.IsLoggedIn() {
		die("not logged in: run 'ackagent login' first")
	}

	// Get key name
	if sshName == "" {
		die("--name is required for key generation")
	}

	// Get algorithm
	if sshType != config.AlgorithmP256 && sshType != config.AlgorithmEd25519 {
		die("invalid key type: %s (use 'ecdsa' or 'ed25519')", sshType)
	}

	// Check for label uniqueness among SSH keys
	if !cfg.IsLabelUnique(config.KeyPurposeSSH, sshName) {
		die("SSH key with name %q already exists. Use a different --name", sshName)
	}

	// Get output path
	outputPath := sshOutput
	if outputPath == "" {
		// Default to ~/.ssh/<name>
		home, err := os.UserHomeDir()
		if err != nil {
			die("failed to get home directory: %v", err)
		}
		outputPath = filepath.Join(home, ".ssh", sshName)
	}

	// Expand ~ in path
	if strings.HasPrefix(outputPath, "~/") {
		home, _ := os.UserHomeDir()
		outputPath = filepath.Join(home, outputPath[2:])
	}

	// Check if output files already exist
	privateKeyPath := outputPath
	publicKeyPath := outputPath + ".pub"
	if _, err := os.Stat(privateKeyPath); err == nil {
		die("file already exists: %s", privateKeyPath)
	}
	if _, err := os.Stat(publicKeyPath); err == nil {
		die("file already exists: %s", publicKeyPath)
	}

	// Ensure parent directory exists
	parentDir := filepath.Dir(outputPath)
	if err := os.MkdirAll(parentDir, 0700); err != nil {
		die("failed to create directory %s: %v", parentDir, err)
	}

	// Generate key on iOS
	algorithmDisplay := "P-256 ECDSA"
	if sshType == config.AlgorithmEd25519 {
		algorithmDisplay = "Ed25519"
	}
	fmt.Fprintf(os.Stderr, "Generating %s SSH key on iOS...\n", algorithmDisplay)
	keyMeta, err := ssh.EnrollSSHKey(cfg, sshName, sshType)
	if err != nil {
		die("failed to generate key: %v", err)
	}

	// Save key metadata to config
	cfg.AddKey(*keyMeta)
	if err := cfg.Save(); err != nil {
		die("failed to save config: %v", err)
	}

	// Build key handle
	userAccount := cfg.UserAccount()
	keyHandle := ssh.BuildKeyHandle(keyMeta.IOSKeyID, userAccount.UserID, ssh.DefaultApplication)

	// Write key files
	if err := ssh.WriteKeyFiles(privateKeyPath, publicKeyPath, keyMeta.PublicKey, keyHandle, ssh.DefaultApplication, sshName, keyMeta.IsEd25519()); err != nil {
		die("%v", err)
	}

	sshFP := computeSSHFP(keyMeta)
	fmt.Fprintf(os.Stderr, "\nSSH key generated successfully!\n\n")
	fmt.Fprintf(os.Stderr, "Private key: %s\n", privateKeyPath)
	fmt.Fprintf(os.Stderr, "Public key:  %s\n", publicKeyPath)
	fmt.Fprintf(os.Stderr, "Fingerprint: %s\n", sshFP)
	fmt.Fprintf(os.Stderr, "Algorithm:   %s\n", algorithmDisplay)
	skProviderPath, skFound := findSKProviderPath()
	if !skFound {
		fmt.Fprintf(os.Stderr, "\nWARNING: SecurityKeyProvider library not found.\n")
		fmt.Fprintf(os.Stderr, "Install it to %s before using SSH.\n", skProviderPath)
	}
	fmt.Fprintf(os.Stderr, "\nUsage:\n")
	fmt.Fprintf(os.Stderr, "  # Add to SSH config (~/.ssh/config)\n")
	fmt.Fprintf(os.Stderr, "  Host *\n")
	fmt.Fprintf(os.Stderr, "    IdentityFile %s\n", privateKeyPath)
	fmt.Fprintf(os.Stderr, "    SecurityKeyProvider %s\n", skProviderPath)
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  # Or use directly\n")
	fmt.Fprintf(os.Stderr, "  ssh -i %s -o SecurityKeyProvider=%s user@host\n", privateKeyPath, skProviderPath)
}

// findSKProviderPath returns the path to the SecurityKeyProvider shared library,
// searching known install locations in priority order. If the library is not found,
// it returns the platform default path and found=false.
func findSKProviderPath() (path string, found bool) {
	var libName string
	if runtime.GOOS == "darwin" {
		libName = "libackagent-sk.dylib"
	} else {
		libName = "libackagent-sk.so"
	}

	// Search known install locations in priority order.
	searchPaths := []string{
		filepath.Join("/opt/homebrew/lib", libName),              // Homebrew (macOS Apple Silicon)
		filepath.Join("/usr/local/lib", libName),                 // .pkg (macOS), Homebrew Intel (macOS), deb/rpm/tarball (Linux)
		filepath.Join("/home/linuxbrew/.linuxbrew/lib", libName), // Homebrew (Linux)
	}

	for _, p := range searchPaths {
		if _, err := os.Stat(p); err == nil {
			return p, true
		}
	}

	// Default: /usr/local/lib is the standard install location.
	return filepath.Join("/usr/local/lib", libName), false
}

func runSSHListKeys(cfg *config.Config) {
	sshKeys := cfg.KeysForPurpose(config.KeyPurposeSSH)

	if len(sshKeys) == 0 {
		fmt.Fprintf(os.Stderr, "No SSH keys enrolled.\n")
		fmt.Fprintf(os.Stderr, "\nTo generate a new key:\n")
		fmt.Fprintf(os.Stderr, "  ackagent ssh --generate-key -n <name> -o <path>\n")
		return
	}

	if len(sshKeys) == 1 {
		fmt.Fprintf(os.Stderr, "Enrolled SSH key:\n\n")
	} else {
		fmt.Fprintf(os.Stderr, "Enrolled SSH keys (%d):\n\n", len(sshKeys))
	}

	for i, k := range sshKeys {
		fp := computeSSHFP(&k)
		if len(sshKeys) > 1 {
			fmt.Printf("[%d] %s\n", i+1, k.Label)
			fmt.Printf("    Fingerprint: %s\n", fp)
			fmt.Printf("    Algorithm:   %s\n", k.Algorithm)
			fmt.Printf("    Created:     %s\n", k.CreatedAt.Format("2006-01-02 15:04:05"))
		} else {
			fmt.Printf("Label:       %s\n", k.Label)
			fmt.Printf("Fingerprint: %s\n", fp)
			fmt.Printf("Algorithm:   %s\n", k.Algorithm)
			fmt.Printf("Created:     %s\n", k.CreatedAt.Format("2006-01-02 15:04:05"))
		}
		fmt.Println()
	}
}

func runSSHExportKey(cfg *config.Config) {
	if !cfg.IsLoggedIn() {
		die("not logged in: run 'ackagent login' first")
	}

	// Find key by name or fingerprint
	keyMeta, err := cfg.FindKey(sshKeyQuery)
	if err != nil {
		die("key not found: %s", sshKeyQuery)
	}

	// Verify it's an SSH key
	if keyMeta.Purpose != config.KeyPurposeSSH {
		die("key %q is not an SSH key (purpose: %s)", sshKeyQuery, keyMeta.Purpose)
	}

	// Get output path
	if sshOutput == "" {
		die("--output is required for key export")
	}

	outputPath := sshOutput
	// Expand ~ in path
	if strings.HasPrefix(outputPath, "~/") {
		home, _ := os.UserHomeDir()
		outputPath = filepath.Join(home, outputPath[2:])
	}

	// Check if output files already exist
	privateKeyPath := outputPath
	publicKeyPath := outputPath + ".pub"
	if _, err := os.Stat(privateKeyPath); err == nil {
		die("file already exists: %s", privateKeyPath)
	}
	if _, err := os.Stat(publicKeyPath); err == nil {
		die("file already exists: %s", publicKeyPath)
	}

	// Ensure parent directory exists
	parentDir := filepath.Dir(outputPath)
	if err := os.MkdirAll(parentDir, 0700); err != nil {
		die("failed to create directory %s: %v", parentDir, err)
	}

	// Build key handle
	userAccount := cfg.UserAccount()
	keyHandle := ssh.BuildKeyHandle(keyMeta.IOSKeyID, userAccount.UserID, ssh.DefaultApplication)

	// Write key files
	if err := ssh.WriteKeyFiles(privateKeyPath, publicKeyPath, keyMeta.PublicKey, keyHandle, ssh.DefaultApplication, keyMeta.Label, keyMeta.IsEd25519()); err != nil {
		die("%v", err)
	}

	exportFP := computeSSHFP(keyMeta)
	fmt.Fprintf(os.Stderr, "SSH key exported successfully!\n\n")
	fmt.Fprintf(os.Stderr, "Private key: %s\n", privateKeyPath)
	fmt.Fprintf(os.Stderr, "Public key:  %s\n", publicKeyPath)
	fmt.Fprintf(os.Stderr, "Fingerprint: %s\n", exportFP)
}

// computeSSHFP computes the SSH fingerprint (SHA256:base64) from a KeyMetadata.
func computeSSHFP(key *config.KeyMetadata) string {
	if len(key.PublicKey) == 0 {
		return key.Hex()
	}
	if key.IsEd25519() {
		return ssh.ComputeSSHFingerprintEd25519(key.PublicKey, ssh.DefaultApplication)
	}
	return ssh.ComputeSSHFingerprint(key.PublicKey, ssh.DefaultApplication)
}
