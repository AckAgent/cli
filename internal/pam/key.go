package pam

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// SigningKey errors.
var (
	ErrInvalidPEM     = errors.New("invalid PEM format")
	ErrInvalidKeyType = errors.New("invalid key type (expected EC PRIVATE KEY)")
	ErrSigningFailed  = errors.New("signing failed")
)

// SigningKey is an ECDSA P-256 signing key for PAM authentication.
// The PAM module uses this key to authenticate with the login service.
type SigningKey struct {
	privateKey   *ecdsa.PrivateKey
	publicKeyHex string
}

// LoadSigningKey loads a signing key from a PEM file.
// The file should contain a PKCS#8-encoded EC private key.
// The path is validated for safety: it must reside under AllowedConfigDir,
// must not contain ".." components, and must have secure ownership and permissions.
func LoadSigningKey(path string) (*SigningKey, error) {
	resolved, err := validateConfigPath(path)
	if err != nil {
		return nil, err
	}

	if err := validateFilePermissions(resolved); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(resolved)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	return ParseSigningKeyPEM(data)
}

// LoadSigningKeyUnsafe loads a signing key from any path without path or
// permission validation. This is intended only for testing and development.
func LoadSigningKeyUnsafe(path string) (*SigningKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	return ParseSigningKeyPEM(data)
}

// ParseSigningKeyPEM parses a signing key from PEM-encoded data.
func ParseSigningKeyPEM(data []byte) (*SigningKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, ErrInvalidPEM
	}

	var privateKey *ecdsa.PrivateKey
	var err error

	switch block.Type {
	case "PRIVATE KEY":
		// PKCS#8 format
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#8 key: %w", err)
		}
		var ok bool
		privateKey, ok = key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, ErrInvalidKeyType
		}

	case "EC PRIVATE KEY":
		// SEC 1 / RFC 5915 format
		privateKey, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC key: %w", err)
		}

	default:
		return nil, fmt.Errorf("%w: got %s", ErrInvalidKeyType, block.Type)
	}

	// Verify it's a P-256 key
	if privateKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("key must be P-256, got %s", privateKey.Curve.Params().Name)
	}

	pubKeyHex := computePublicKeyHex(&privateKey.PublicKey)

	return &SigningKey{
		privateKey:   privateKey,
		publicKeyHex: pubKeyHex,
	}, nil
}

// GenerateSigningKey generates a new P-256 signing key pair.
func GenerateSigningKey() (*SigningKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	pubKeyHex := computePublicKeyHex(&privateKey.PublicKey)

	return &SigningKey{
		privateKey:   privateKey,
		publicKeyHex: pubKeyHex,
	}, nil
}

// PublicKeyHex returns the hex-encoded raw public key bytes (X || Y, 64 bytes).
func (k *SigningKey) PublicKeyHex() string {
	return k.publicKeyHex
}

// Sign signs data with ECDSA P-256.
// Returns the signature in DER format (ASN.1 encoded).
func (k *SigningKey) Sign(data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	return ecdsa.SignASN1(rand.Reader, k.privateKey, hash[:])
}

// SignTokenRequest signs a PAM token request.
// The message format is: 8-byte big-endian timestamp || raw nonce bytes.
func (k *SigningKey) SignTokenRequest(timestamp int64, nonce []byte) ([]byte, error) {
	// Build message: 8-byte big-endian timestamp + raw nonce bytes
	message := make([]byte, 8+len(nonce))
	binary.BigEndian.PutUint64(message[:8], uint64(timestamp))
	copy(message[8:], nonce)

	return k.Sign(message)
}

// PublicKeyDER returns the public key in DER format.
func (k *SigningKey) PublicKeyDER() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(&k.privateKey.PublicKey)
}

// PublicKey returns the ECDSA public key.
func (k *SigningKey) PublicKey() *ecdsa.PublicKey {
	return &k.privateKey.PublicKey
}

// ToPEM exports the private key as PKCS#8 PEM.
func (k *SigningKey) ToPEM() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}

	return pem.EncodeToMemory(block), nil
}

// SaveToFile saves the private key to a PEM file.
func (k *SigningKey) SaveToFile(path string) error {
	data, err := k.ToPEM()
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

// computePublicKeyHex computes the hex-encoded raw public key bytes (X || Y, 64 bytes).
func computePublicKeyHex(publicKey *ecdsa.PublicKey) string {
	// Raw P-256 public key: 32 bytes X || 32 bytes Y
	rawBytes := make([]byte, 64)
	publicKey.X.FillBytes(rawBytes[:32])
	publicKey.Y.FillBytes(rawBytes[32:])
	return hex.EncodeToString(rawBytes)
}
