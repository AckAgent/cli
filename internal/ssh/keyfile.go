// Package ssh provides SSH key file serialization for OpenSSH sk-ecdsa keys.
package ssh

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

const (
	// SSHKeyTypeECDSA is the OpenSSH key type for ECDSA security keys
	SSHKeyTypeECDSA = "sk-ecdsa-sha2-nistp256@openssh.com"
	// SSHKeyTypeEd25519 is the OpenSSH key type for Ed25519 security keys
	SSHKeyTypeEd25519 = "sk-ssh-ed25519@openssh.com"

	// DefaultApplication is the default SSH application string
	DefaultApplication = "ssh:"

	// KeyHandleMagic is the magic bytes for AckAgent key handles (little-endian "APPR")
	KeyHandleMagic uint32 = 0x41505052
)

// KeyHandleData contains the data stored in a key handle
type KeyHandleData struct {
	Version     int    `json:"v"`
	IOSKeyID    string `json:"k"`
	UserID      string `json:"d"`
	Application string `json:"a"`
	CreatedAt   int64  `json:"t"`
}

// BuildKeyHandle creates an OpenSSH-compatible key handle blob.
// Format: [4-byte magic LE][4-byte length LE][JSON payload]
func BuildKeyHandle(iosKeyID, userID, application string) []byte {
	data := KeyHandleData{
		Version:     1,
		IOSKeyID:    iosKeyID,
		UserID:      userID,
		Application: application,
		CreatedAt:   time.Now().Unix(),
	}

	jsonData, _ := json.Marshal(data)

	// Format: [4-byte magic LE][4-byte length LE][JSON data]
	result := make([]byte, 8+len(jsonData))

	// Write magic in little-endian (appears as "RPPA" in raw bytes)
	binary.LittleEndian.PutUint32(result[0:4], KeyHandleMagic)
	// Write length in little-endian
	binary.LittleEndian.PutUint32(result[4:8], uint32(len(jsonData)))
	copy(result[8:], jsonData)

	return result
}

// BuildPublicKeyBlob creates an SSH public key blob for sk-ecdsa keys.
// publicKey should be 33 bytes (compressed P-256: 0x02/0x03 || X).
// SSH wire format requires uncompressed EC points, so we decompress internally.
func BuildPublicKeyBlob(publicKey []byte, application string) []byte {
	var buf bytes.Buffer

	// Key type string
	writeSSHString(&buf, []byte(SSHKeyTypeECDSA))

	// Curve name
	writeSSHString(&buf, []byte("nistp256"))

	// SSH requires uncompressed EC point (0x04 || X || Y) - decompress
	point := decompressForSSH(publicKey)
	writeSSHString(&buf, point)

	// Application
	writeSSHString(&buf, []byte(application))

	return buf.Bytes()
}

// ComputeSSHFingerprint computes the SSH fingerprint from a public key.
// Returns "SHA256:<base64>" format without trailing padding.
func ComputeSSHFingerprint(publicKey []byte, application string) string {
	blob := BuildPublicKeyBlob(publicKey, application)
	hash := sha256.Sum256(blob)
	// Base64 without trailing '=' padding
	b64 := base64.RawStdEncoding.EncodeToString(hash[:])
	return "SHA256:" + b64
}

// BuildPublicKeyBlobEd25519 creates an SSH public key blob for sk-ssh-ed25519 keys.
// publicKey should be 32 bytes.
func BuildPublicKeyBlobEd25519(publicKey []byte, application string) []byte {
	var buf bytes.Buffer

	// Key type string
	writeSSHString(&buf, []byte(SSHKeyTypeEd25519))

	// Ed25519 public key (32 bytes directly, no curve name, no prefix)
	writeSSHString(&buf, publicKey)

	// Application
	writeSSHString(&buf, []byte(application))

	return buf.Bytes()
}

// ComputeSSHFingerprintEd25519 computes the SSH fingerprint for an Ed25519 public key.
// Returns "SHA256:<base64>" format without trailing padding.
func ComputeSSHFingerprintEd25519(publicKey []byte, application string) string {
	blob := BuildPublicKeyBlobEd25519(publicKey, application)
	hash := sha256.Sum256(blob)
	b64 := base64.RawStdEncoding.EncodeToString(hash[:])
	return "SHA256:" + b64
}

// WritePublicKeyFile writes an OpenSSH public key file (.pub).
// Format: sk-ecdsa-sha2-nistp256@openssh.com <base64-blob> <comment>
func WritePublicKeyFile(path string, publicKey []byte, application, comment string) error {
	blob := BuildPublicKeyBlob(publicKey, application)
	line := fmt.Sprintf("%s %s %s\n", SSHKeyTypeECDSA, base64.StdEncoding.EncodeToString(blob), comment)
	return os.WriteFile(path, []byte(line), 0644)
}

// WritePublicKeyFileEd25519 writes an OpenSSH public key file (.pub) for Ed25519 keys.
// Format: sk-ssh-ed25519@openssh.com <base64-blob> <comment>
func WritePublicKeyFileEd25519(path string, publicKey []byte, application, comment string) error {
	blob := BuildPublicKeyBlobEd25519(publicKey, application)
	line := fmt.Sprintf("%s %s %s\n", SSHKeyTypeEd25519, base64.StdEncoding.EncodeToString(blob), comment)
	return os.WriteFile(path, []byte(line), 0644)
}

// WritePrivateKeyFile writes an OpenSSH private key file with key handle.
// This is NOT the actual private key - it contains a key handle that references
// the real key stored on iOS.
func WritePrivateKeyFile(path string, publicKey, keyHandle []byte, application, comment string) error {
	content, err := BuildPrivateKeyContent(publicKey, keyHandle, application, comment)
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0600)
}

// WritePrivateKeyFileEd25519 writes an OpenSSH private key file for Ed25519 keys.
// This is NOT the actual private key - it contains a key handle that references
// the real key stored on iOS.
func WritePrivateKeyFileEd25519(path string, publicKey, keyHandle []byte, application, comment string) error {
	content, err := BuildPrivateKeyContentEd25519(publicKey, keyHandle, application, comment)
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0600)
}

// BuildPrivateKeyContent builds the OpenSSH private key file content.
func BuildPrivateKeyContent(publicKey, keyHandle []byte, application, comment string) (string, error) {
	pubBlob := BuildPublicKeyBlob(publicKey, application)

	var buf bytes.Buffer

	// 1. AUTH_MAGIC: "openssh-key-v1" + null byte
	buf.WriteString("openssh-key-v1")
	buf.WriteByte(0x00)

	// 2. Cipher: "none" (length-prefixed string)
	writeSSHString(&buf, []byte("none"))

	// 3. KDF: "none"
	writeSSHString(&buf, []byte("none"))

	// 4. KDF options: empty string
	writeSSHString(&buf, []byte{})

	// 5. Number of keys: 1 (big-endian uint32)
	writeUint32BE(&buf, 1)

	// 6. Public key blob (length-prefixed)
	writeSSHString(&buf, pubBlob)

	// 7. Private section (length-prefixed)
	privSection := buildPrivateSection(publicKey, keyHandle, application, comment)
	writeSSHString(&buf, privSection)

	// 8. PEM encode with line wrapping at 70 chars
	encoded := base64.StdEncoding.EncodeToString(buf.Bytes())
	wrapped := wrapBase64(encoded, 70)

	return "-----BEGIN OPENSSH PRIVATE KEY-----\n" + wrapped + "-----END OPENSSH PRIVATE KEY-----\n", nil
}

// BuildPrivateKeyContentEd25519 builds the OpenSSH private key file content for Ed25519 keys.
func BuildPrivateKeyContentEd25519(publicKey, keyHandle []byte, application, comment string) (string, error) {
	pubBlob := BuildPublicKeyBlobEd25519(publicKey, application)

	var buf bytes.Buffer

	// 1. AUTH_MAGIC: "openssh-key-v1" + null byte
	buf.WriteString("openssh-key-v1")
	buf.WriteByte(0x00)

	// 2. Cipher: "none" (length-prefixed string)
	writeSSHString(&buf, []byte("none"))

	// 3. KDF: "none"
	writeSSHString(&buf, []byte("none"))

	// 4. KDF options: empty string
	writeSSHString(&buf, []byte{})

	// 5. Number of keys: 1 (big-endian uint32)
	writeUint32BE(&buf, 1)

	// 6. Public key blob (length-prefixed)
	writeSSHString(&buf, pubBlob)

	// 7. Private section (length-prefixed)
	privSection := buildPrivateSectionEd25519(publicKey, keyHandle, application, comment)
	writeSSHString(&buf, privSection)

	// 8. PEM encode with line wrapping at 70 chars
	encoded := base64.StdEncoding.EncodeToString(buf.Bytes())
	wrapped := wrapBase64(encoded, 70)

	return "-----BEGIN OPENSSH PRIVATE KEY-----\n" + wrapped + "-----END OPENSSH PRIVATE KEY-----\n", nil
}

// buildPrivateSection builds the private section of an OpenSSH key file.
func buildPrivateSection(publicKey, keyHandle []byte, application, comment string) []byte {
	var buf bytes.Buffer

	// Two matching random uint32 check values (big-endian)
	checkBytes := make([]byte, 4)
	rand.Read(checkBytes)
	checkInt := binary.BigEndian.Uint32(checkBytes)
	writeUint32BE(&buf, checkInt)
	writeUint32BE(&buf, checkInt)

	// Key type
	writeSSHString(&buf, []byte(SSHKeyTypeECDSA))

	// Curve name
	writeSSHString(&buf, []byte("nistp256"))

	// SSH requires uncompressed EC point (0x04 || X || Y) - decompress
	point := decompressForSSH(publicKey)
	writeSSHString(&buf, point)

	// Application
	writeSSHString(&buf, []byte(application))

	// Flags byte (0x01 = user presence required)
	buf.WriteByte(0x01)

	// Key handle (length-prefixed)
	writeSSHString(&buf, keyHandle)

	// Reserved (empty string)
	writeSSHString(&buf, []byte{})

	// Comment
	writeSSHString(&buf, []byte(comment))

	// Padding to 8-byte block size (1, 2, 3, 4...)
	blockSize := 8
	for i := 1; buf.Len()%blockSize != 0; i++ {
		buf.WriteByte(byte(i))
	}

	return buf.Bytes()
}

// buildPrivateSectionEd25519 builds the private section of an OpenSSH key file for Ed25519 keys.
func buildPrivateSectionEd25519(publicKey, keyHandle []byte, application, comment string) []byte {
	var buf bytes.Buffer

	// Two matching random uint32 check values (big-endian)
	checkBytes := make([]byte, 4)
	rand.Read(checkBytes)
	checkInt := binary.BigEndian.Uint32(checkBytes)
	writeUint32BE(&buf, checkInt)
	writeUint32BE(&buf, checkInt)

	// Key type
	writeSSHString(&buf, []byte(SSHKeyTypeEd25519))

	// Ed25519 public key (32 bytes directly, no curve name, no prefix)
	writeSSHString(&buf, publicKey)

	// Application
	writeSSHString(&buf, []byte(application))

	// Flags byte (0x01 = user presence required)
	buf.WriteByte(0x01)

	// Key handle (length-prefixed)
	writeSSHString(&buf, keyHandle)

	// Reserved (empty string)
	writeSSHString(&buf, []byte{})

	// Comment
	writeSSHString(&buf, []byte(comment))

	// Padding to 8-byte block size (1, 2, 3, 4...)
	blockSize := 8
	for i := 1; buf.Len()%blockSize != 0; i++ {
		buf.WriteByte(byte(i))
	}

	return buf.Bytes()
}

// decompressForSSH decompresses a compressed P-256 public key (33 bytes) to
// uncompressed SEC1 format (65 bytes: 0x04 || X || Y) as required by SSH wire format.
func decompressForSSH(compressed []byte) []byte {
	if len(compressed) == 33 {
		x, y := elliptic.UnmarshalCompressed(elliptic.P256(), compressed)
		if x != nil {
			return elliptic.Marshal(elliptic.P256(), x, y)
		}
	}
	// Fallback: if already uncompressed or invalid, return as-is
	return compressed
}

// writeSSHString writes a length-prefixed string (SSH wire format, big-endian length).
func writeSSHString(buf *bytes.Buffer, data []byte) {
	writeUint32BE(buf, uint32(len(data)))
	buf.Write(data)
}

// writeUint32BE writes a uint32 in big-endian format.
func writeUint32BE(buf *bytes.Buffer, v uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	buf.Write(b[:])
}

// wrapBase64 wraps a base64 string at the specified line length.
func wrapBase64(s string, lineLen int) string {
	var result bytes.Buffer
	for i := 0; i < len(s); i += lineLen {
		end := min(i+lineLen, len(s))
		result.WriteString(s[i:end])
		result.WriteByte('\n')
	}
	return result.String()
}

// WriteKeyFiles writes both private and public key files for an SSH key.
// It automatically selects the correct format based on whether the key is Ed25519 or ECDSA.
// If writing fails partway through, it cleans up any files that were created.
func WriteKeyFiles(privateKeyPath, publicKeyPath string, publicKey, keyHandle []byte, application, comment string, isEd25519 bool) error {
	if isEd25519 {
		if err := WritePrivateKeyFileEd25519(privateKeyPath, publicKey, keyHandle, application, comment); err != nil {
			return fmt.Errorf("failed to write private key: %w", err)
		}
		if err := WritePublicKeyFileEd25519(publicKeyPath, publicKey, application, comment); err != nil {
			os.Remove(privateKeyPath)
			return fmt.Errorf("failed to write public key: %w", err)
		}
	} else {
		if err := WritePrivateKeyFile(privateKeyPath, publicKey, keyHandle, application, comment); err != nil {
			return fmt.Errorf("failed to write private key: %w", err)
		}
		if err := WritePublicKeyFile(publicKeyPath, publicKey, application, comment); err != nil {
			os.Remove(privateKeyPath)
			return fmt.Errorf("failed to write public key: %w", err)
		}
	}
	return nil
}
