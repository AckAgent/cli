// Package crypto provides end-to-end encryption using P-256 ECDH key exchange
// and ChaCha20-Poly1305 authenticated encryption.
package crypto

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/ackagent/cli/internal/shared/log"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

var cryptoLog = log.New("crypto")

const (
	// PrivateKeySize is the size of P-256 private keys in bytes
	PrivateKeySize = 32

	// PublicKeySize is the size of P-256 public keys in bytes (compressed: 0x02/0x03 || X)
	PublicKeySize = 33

	// UncompressedPublicKeySize is the size of uncompressed P-256 public keys (0x04 || X || Y)
	UncompressedPublicKeySize = 65

	// KeySize is the size of symmetric keys in bytes (for ChaCha20-Poly1305)
	KeySize = 32

	// NonceSize is the size of ChaCha20-Poly1305 nonces
	NonceSize = chacha20poly1305.NonceSize

	// hkdfRequestInfo is used for per-request key derivation (forward secrecy)
	hkdfRequestInfo = "signer-request-v1"

	// hkdfResponseInfo is used for per-response key derivation (forward secrecy)
	hkdfResponseInfo = "signer-response-v1"
)

var (
	ErrInvalidKeySize   = errors.New("invalid key size")
	ErrInvalidNonceSize = errors.New("invalid nonce size")
	ErrDecryptionFailed = errors.New("decryption failed")
	ErrKeyDeriveFailed  = errors.New("key derivation failed")
)

// KeyPair represents a P-256 ECDH key pair
type KeyPair struct {
	PrivateKey [PrivateKeySize]byte
	PublicKey  [PublicKeySize]byte
}

// GenerateKeyPair generates a new P-256 ECDH key pair.
// The public key is stored in compressed SEC1 format (33 bytes).
func GenerateKeyPair() (*KeyPair, error) {
	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	var kp KeyPair

	// Copy private key bytes
	privBytes := privateKey.Bytes()
	defer clear(privBytes) // Zero ephemeral private key bytes after copy
	copy(kp.PrivateKey[:], privBytes)

	// Get uncompressed public key (65 bytes) and compress to 33 bytes
	pubBytes := privateKey.PublicKey().Bytes()
	compressed, err := CompressPublicKey(pubBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to compress public key: %w", err)
	}
	copy(kp.PublicKey[:], compressed)

	return &kp, nil
}

// CompressPublicKey compresses an uncompressed P-256 public key (65 bytes: 0x04 || X || Y)
// to compressed SEC1 format (33 bytes: 0x02/0x03 || X).
func CompressPublicKey(uncompressed []byte) ([]byte, error) {
	return CompressP256PublicKey(uncompressed)
}

// DecompressPublicKey decompresses a compressed P-256 public key (33 bytes: 0x02/0x03 || X)
// to uncompressed format (65 bytes: 0x04 || X || Y).
func DecompressPublicKey(compressed []byte) ([]byte, error) {
	return DecompressP256PublicKey(compressed)
}

// SharedSecret computes the P-256 ECDH shared secret from our private key
// and their public key. The public key is accepted in compressed format (33 bytes)
// and decompressed internally for the ECDH operation.
func SharedSecret(privateKeyBytes, theirPublicKeyBytes []byte) ([]byte, error) {
	if len(privateKeyBytes) != PrivateKeySize {
		return nil, ErrInvalidKeySize
	}
	if len(theirPublicKeyBytes) != PublicKeySize {
		return nil, ErrInvalidKeySize
	}

	// Parse our private key
	privateKey, err := ecdh.P256().NewPrivateKey(privateKeyBytes)
	if err != nil {
		return nil, err
	}

	// Decompress their public key from 33 bytes to 65 bytes for ecdh.P256()
	uncompressed, err := DecompressPublicKey(theirPublicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress public key: %w", err)
	}

	// Parse their uncompressed public key
	theirPublicKey, err := ecdh.P256().NewPublicKey(uncompressed)
	if err != nil {
		return nil, err
	}

	// Perform ECDH
	sharedSecret, err := privateKey.ECDH(theirPublicKey)
	if err != nil {
		return nil, err
	}

	return sharedSecret, nil
}

// DeriveRequestKey derives a per-request encryption key for forward secrecy.
// Desktop uses: DeriveRequestKey(ephemeralPrivate, signerIdentityPublic, requestID)
// Signer uses: DeriveRequestKey(identityPrivate, desktopEphemeralPublic, requestID)
func DeriveRequestKey(ourPrivate, theirPublic []byte, requestID []byte) ([]byte, error) {
	cryptoLog.Debug("deriving request key salt=%d bytes", len(requestID))

	// Compute ECDH shared secret
	sharedSecret, err := SharedSecret(ourPrivate, theirPublic)
	if err != nil {
		cryptoLog.Error("ECDH failed: %v", err)
		return nil, err
	}
	defer clear(sharedSecret) // Zero shared secret after key derivation

	// Use request ID as salt for HKDF
	hkdfReader := hkdf.New(sha256.New, sharedSecret, requestID, []byte(hkdfRequestInfo))

	key := make([]byte, KeySize)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		cryptoLog.Error("HKDF failed: %v", err)
		return nil, ErrKeyDeriveFailed
	}

	cryptoLog.Debug("request key derived")
	return key, nil
}

// DeriveResponseKey derives a per-response encryption key for forward secrecy.
// Signer uses: DeriveResponseKey(signerEphemeralPrivate, desktopEphemeralPublic, requestID)
// Desktop uses: DeriveResponseKey(desktopEphemeralPrivate, signerEphemeralPublic, requestID)
func DeriveResponseKey(ourPrivate, theirPublic []byte, requestID []byte) ([]byte, error) {
	// Compute ECDH shared secret
	sharedSecret, err := SharedSecret(ourPrivate, theirPublic)
	if err != nil {
		return nil, err
	}
	defer clear(sharedSecret) // Zero shared secret after key derivation

	// Use request ID as salt for HKDF
	hkdfReader := hkdf.New(sha256.New, sharedSecret, requestID, []byte(hkdfResponseInfo))

	key := make([]byte, KeySize)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, ErrKeyDeriveFailed
	}

	return key, nil
}

// Encrypt encrypts plaintext using ChaCha20-Poly1305 with the given key.
// Returns ciphertext and nonce.
func Encrypt(key, plaintext, additionalData []byte) (ciphertext, nonce []byte, err error) {
	cryptoLog.Debug("encrypting plaintext=%d bytes", len(plaintext))

	if len(key) != KeySize {
		cryptoLog.Error("invalid key size: %d", len(key))
		return nil, nil, ErrInvalidKeySize
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		cryptoLog.Error("failed to create AEAD: %v", err)
		return nil, nil, err
	}

	// Generate random nonce
	nonce = make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		cryptoLog.Error("failed to generate nonce: %v", err)
		return nil, nil, err
	}

	// Encrypt
	ciphertext = aead.Seal(nil, nonce, plaintext, additionalData)

	cryptoLog.Debug("encrypted ciphertext=%d bytes", len(ciphertext))
	return ciphertext, nonce, nil
}

// Decrypt decrypts ciphertext using ChaCha20-Poly1305 with the given key.
func Decrypt(key, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	cryptoLog.Debug("decrypting ciphertext=%d bytes", len(ciphertext))

	if len(key) != KeySize {
		cryptoLog.Error("invalid key size: %d", len(key))
		return nil, ErrInvalidKeySize
	}
	if len(nonce) != NonceSize {
		cryptoLog.Error("invalid nonce size: %d", len(nonce))
		return nil, ErrInvalidNonceSize
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		cryptoLog.Error("failed to create AEAD: %v", err)
		return nil, err
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		cryptoLog.Error("decryption failed")
		return nil, ErrDecryptionFailed
	}

	cryptoLog.Debug("decrypted plaintext=%d bytes", len(plaintext))
	return plaintext, nil
}

// GenerateRandomBytes generates n random bytes
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// VerifyAttestationSignature verifies an attestation signature from an iOS device.
// iOS devices sign responses with their Secure Enclave P-256 signing key.
//
// The signature is over: requestID || SHA256(encryptedResponse)
//
// Parameters:
//   - signingPublicKey: Compressed P-256 public key (33 bytes: 0x02/0x03 || X)
//   - requestID: Request ID bytes (typically 16 bytes UUID)
//   - encryptedResponse: The encrypted response blob
//   - signature: ECDSA signature (DER-encoded or raw 64-byte r||s)
func VerifyAttestationSignature(signingPublicKey, requestID, encryptedResponse, signature []byte) (bool, error) {
	if len(signingPublicKey) != PublicKeySize {
		return false, fmt.Errorf("signing public key must be %d bytes (compressed P-256), got %d", PublicKeySize, len(signingPublicKey))
	}

	// Decompress the public key to get X, Y coordinates
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), signingPublicKey)
	if x == nil || y == nil {
		return false, errors.New("invalid compressed P-256 signing public key")
	}

	// Build message: requestID || SHA256(encryptedResponse)
	responseHash := sha256.Sum256(encryptedResponse)
	message := make([]byte, len(requestID)+32)
	copy(message, requestID)
	copy(message[len(requestID):], responseHash[:])

	// Hash the message for ECDSA verification
	msgHash := sha256.Sum256(message)

	pubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	// Try DER-encoded signature first
	if verifyAttestDER(pubKey, msgHash[:], signature) {
		return true, nil
	}

	// Try raw r||s signature (64 bytes)
	if len(signature) == 64 {
		if verifyAttestRaw(pubKey, msgHash[:], signature) {
			return true, nil
		}
	}

	return false, nil
}

// verifyAttestDER verifies a DER-encoded ECDSA signature for attestation
func verifyAttestDER(pubKey *ecdsa.PublicKey, hash, sig []byte) bool {
	// Try to parse as DER
	if len(sig) < 8 || sig[0] != 0x30 {
		return false
	}

	r, s, err := parseAttestDER(sig)
	if err != nil {
		return false
	}

	// Apply low-S normalization to prevent signature malleability
	s = NormalizeLowS(s, pubKey.Curve)

	return ecdsa.Verify(pubKey, hash, r, s)
}

// verifyAttestRaw verifies a raw r||s signature (64 bytes) for attestation
func verifyAttestRaw(pubKey *ecdsa.PublicKey, hash, sig []byte) bool {
	if len(sig) != 64 {
		return false
	}

	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])

	// Apply low-S normalization to prevent signature malleability
	s = NormalizeLowS(s, pubKey.Curve)

	return ecdsa.Verify(pubKey, hash, r, s)
}

// parseAttestDER parses a DER-encoded ECDSA signature for attestation verification
func parseAttestDER(der []byte) (*big.Int, *big.Int, error) {
	if len(der) < 8 || der[0] != 0x30 {
		return nil, nil, errors.New("invalid DER signature")
	}

	pos := 2

	if der[pos] != 0x02 {
		return nil, nil, errors.New("invalid DER: missing R tag")
	}
	pos++
	rLen := int(der[pos])
	pos++
	if pos+rLen > len(der) {
		return nil, nil, errors.New("invalid DER: R overflow")
	}
	r := new(big.Int).SetBytes(der[pos : pos+rLen])
	pos += rLen

	if pos >= len(der) || der[pos] != 0x02 {
		return nil, nil, errors.New("invalid DER: missing S tag")
	}
	pos++
	if pos >= len(der) {
		return nil, nil, errors.New("invalid DER: S length missing")
	}
	sLen := int(der[pos])
	pos++
	if pos+sLen > len(der) {
		return nil, nil, errors.New("invalid DER: S overflow")
	}
	s := new(big.Int).SetBytes(der[pos : pos+sLen])

	return r, s, nil
}
