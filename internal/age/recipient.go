// Package age implements age encryption plugin support for AckAgent.
// It provides an age plugin that uses iOS-stored X25519 keys for decryption.
package age

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	// StanzaType is the age stanza type for ackagent recipients
	StanzaType = "ackagent"

	// RecipientPrefix is the HRP (human-readable part) for recipient encoding
	RecipientPrefix = "age1ackagent"

	// IdentityPrefix is the HRP for identity encoding
	IdentityPrefix = "AGE-PLUGIN-ACKAGENT-"

	// hkdfLabel is the HKDF info string used by age for X25519
	hkdfLabel = "age-encryption.org/v1/X25519"
)

// Recipient implements age.Recipient for ackagent keys.
// It wraps file keys using X25519 ECDH with the recipient's public key.
type Recipient struct {
	// PublicKey is the X25519 public key (32 bytes)
	PublicKey []byte
}

// Ensure Recipient implements age.Recipient
var _ age.Recipient = (*Recipient)(nil)

// ParseRecipient parses a recipient string in the format "age1ackagent1..."
func ParseRecipient(s string) (*Recipient, error) {
	if !strings.HasPrefix(strings.ToLower(s), RecipientPrefix) {
		return nil, fmt.Errorf("invalid ackagent recipient: must start with %s", RecipientPrefix)
	}

	// Decode bech32
	_, data, err := bech32Decode(s)
	if err != nil {
		return nil, fmt.Errorf("invalid recipient encoding: %w", err)
	}

	if len(data) != 32 {
		return nil, fmt.Errorf("invalid recipient: expected 32 bytes, got %d", len(data))
	}

	return &Recipient{PublicKey: data}, nil
}

// String returns the bech32-encoded recipient string
func (r *Recipient) String() string {
	encoded, err := bech32Encode(RecipientPrefix, r.PublicKey)
	if err != nil {
		return ""
	}
	return encoded
}

// Wrap encrypts a file key to this recipient.
// It generates an ephemeral X25519 keypair, performs ECDH, derives a wrapping key,
// and encrypts the file key.
func (r *Recipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	// Generate ephemeral keypair
	ephemeralPrivate := make([]byte, curve25519.ScalarSize)
	if _, err := io.ReadFull(secureRandom, ephemeralPrivate); err != nil {
		return nil, err
	}

	ephemeralPublic, err := curve25519.X25519(ephemeralPrivate, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	// Perform ECDH: shared = X25519(ephemeral_private, recipient_public)
	sharedSecret, err := curve25519.X25519(ephemeralPrivate, r.PublicKey)
	if err != nil {
		return nil, err
	}

	// Derive wrapping key using age's HKDF parameters
	// salt = ephemeral_public || recipient_public
	salt := append(ephemeralPublic, r.PublicKey...)
	wrapKey, err := deriveKey(sharedSecret, salt)
	if err != nil {
		return nil, err
	}

	// Encrypt file key with ChaCha20-Poly1305
	aead, err := chacha20poly1305.New(wrapKey)
	if err != nil {
		return nil, err
	}

	// Age uses a zero nonce for wrapping
	nonce := make([]byte, chacha20poly1305.NonceSize)
	wrappedKey := aead.Seal(nil, nonce, fileKey, nil)

	// Create stanza with ephemeral public key as argument
	stanza := &age.Stanza{
		Type: StanzaType,
		Args: []string{base64.RawStdEncoding.EncodeToString(ephemeralPublic)},
		Body: wrappedKey,
	}

	return []*age.Stanza{stanza}, nil
}

// deriveKey derives a 32-byte key using HKDF-SHA256 with age's parameters
func deriveKey(sharedSecret, salt []byte) ([]byte, error) {
	h := hkdf.New(sha256.New, sharedSecret, salt, []byte(hkdfLabel))
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, key); err != nil {
		return nil, err
	}
	return key, nil
}
