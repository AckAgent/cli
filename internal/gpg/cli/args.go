package cli

import (
	"fmt"
	"os"
)

// Mode represents the operation mode.
type Mode int

const (
	ModeSign        Mode = iota // Sign data
	ModeDetach                  // Detached signature
	ModeVerify                  // Verify signature
	ModeDecrypt                 // Decrypt data
	ModeEncrypt                 // Encrypt data
	ModeListKeys                // List keys
	ModeExportKey               // Export public key
	ModeGenerateKey             // Generate new key
	ModeVersion                 // Show version
	ModeHelp                    // Show help
)

// Args holds parsed command-line arguments.
// Note: With Cobra, these are populated directly from pflag variables,
// not from a custom parser.
type Args struct {
	Mode       Mode
	Armor      bool
	StatusFD   int
	InputFile  string
	OutputFile string
	LocalUser  string
	Verbose    bool
	// For key generation
	Name      string // User name for key (--name)
	Email     string // User email for key (--email)
	Algorithm string // Key algorithm: p256 (default) or ed25519 (--type / -t)
	// For encryption
	Recipients []string // Recipient key IDs/emails (--recipient / -r)
	// For verification
	DataFile string // Signed data file (second positional arg for --verify)
}

// StatusWriter writes GPG status messages to a file descriptor.
type StatusWriter struct {
	fd *os.File
}

// NewStatusWriter creates a new status writer for the given file descriptor.
func NewStatusWriter(fd int) *StatusWriter {
	if fd < 0 {
		return &StatusWriter{}
	}
	return &StatusWriter{fd: os.NewFile(uintptr(fd), "status")}
}

// Write writes a status message.
func (sw *StatusWriter) Write(format string, args ...interface{}) {
	if sw.fd == nil {
		return
	}
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(sw.fd, "[GNUPG:] %s\n", msg)
}

// BeginSigning writes the BEGIN_SIGNING status.
func (sw *StatusWriter) BeginSigning() {
	sw.Write("BEGIN_SIGNING")
}

// SigCreated writes the SIG_CREATED status.
// sigType: D=detached, S=standard
// pkAlgo: public key algorithm (19=ECDSA)
// hashAlgo: hash algorithm (8=SHA256)
// sigClass: signature class (00=binary)
// timestamp: Unix timestamp
// fingerprint: key fingerprint
func (sw *StatusWriter) SigCreated(sigType byte, pkAlgo, hashAlgo, sigClass byte, timestamp int64, fingerprint string) {
	sw.Write("SIG_CREATED %c %d %d %02X %d %s", sigType, pkAlgo, hashAlgo, sigClass, timestamp, fingerprint)
}

// NewSig writes a NEWSIG status to indicate a new signature verification is starting.
func (sw *StatusWriter) NewSig() {
	sw.Write("NEWSIG")
}

// GoodSig writes a GOODSIG status for verification.
func (sw *StatusWriter) GoodSig(keyID, userID string) {
	sw.Write("GOODSIG %s %s", keyID, userID)
}

// BadSig writes a BADSIG status for verification.
func (sw *StatusWriter) BadSig(keyID, userID string) {
	sw.Write("BADSIG %s %s", keyID, userID)
}

// NoPublicKey writes a NO_PUBKEY status.
func (sw *StatusWriter) NoPublicKey(keyID string) {
	sw.Write("NO_PUBKEY %s", keyID)
}

// ValidSig writes the VALIDSIG status line that git requires for verify-commit.
// Format per GnuPG DETAILS:
//
//	VALIDSIG <fpr> <sig_created> <sig_expires> <sig_version> <reserved> <reserved> <pubkey_algo> <hash_algo> <sig_class> <primary_fpr>
//
// Git skips 8 fields after fpr to reach primary_fpr (field 10). All 10 fields are required.
func (sw *StatusWriter) ValidSig(fingerprint string, creationTime int64, pkAlgo, hashAlgo byte) {
	sw.Write("VALIDSIG %s %d 0 4 0 0 %d %d 00 %s",
		fingerprint, creationTime, pkAlgo, hashAlgo, fingerprint)
}

// TrustUltimate writes a TRUST_ULTIMATE status line.
// This tells git the key is ultimately trusted (like a self-owned key).
func (sw *StatusWriter) TrustUltimate() {
	sw.Write("TRUST_ULTIMATE 0 shell")
}

// Close closes the status writer.
func (sw *StatusWriter) Close() error {
	if sw.fd != nil {
		return sw.fd.Close()
	}
	return nil
}
