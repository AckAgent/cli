package age

import (
	"encoding/base64"
	"fmt"
	"strings"

	"filippo.io/age"
	"github.com/ackagent/cli/internal/shared/config"
)

// Identity implements age.Identity for ackagent keys.
// It delegates the ECDH operation to iOS for decryption.
type Identity struct {
	// PublicKeyHex is the hex-encoded public key used to look up the key in config
	PublicKeyHex string

	// PublicKey is the X25519 public key (32 bytes)
	PublicKey []byte

	// Config is the CLI config for finding keys and sending requests
	Config *config.Config

	// UnwrapFunc is called to perform the actual unwrap via iOS
	// It receives the ephemeral public key and wrapped key, returns the file key
	UnwrapFunc func(ephemeralPublic, wrappedKey, recipientPublic []byte) ([]byte, error)
}

// Ensure Identity implements age.Identity
var _ age.Identity = (*Identity)(nil)

// ParseIdentity parses an identity string in the format "AGE-PLUGIN-ACKAGENT-1..."
func ParseIdentity(s string) (*Identity, error) {
	upper := strings.ToUpper(s)
	if !strings.HasPrefix(upper, IdentityPrefix) {
		return nil, fmt.Errorf("invalid ackagent identity: must start with %s", IdentityPrefix)
	}

	// The identity contains a key public key hex reference
	// Format: AGE-PLUGIN-ACKAGENT-1<bech32-encoded-publicKeyHex>
	encoded := strings.TrimPrefix(upper, IdentityPrefix)

	// Decode bech32 (use lowercase for decoding)
	_, data, err := bech32Decode(strings.ToLower(IdentityPrefix + encoded))
	if err != nil {
		return nil, fmt.Errorf("invalid identity encoding: %w", err)
	}

	// Data contains the public key hex as bytes
	publicKeyHex := string(data)

	return &Identity{PublicKeyHex: publicKeyHex}, nil
}

// String returns the bech32-encoded identity string
func (i *Identity) String() string {
	// Encode public key hex as bytes
	data := []byte(i.PublicKeyHex)
	encoded, err := bech32Encode(strings.ToLower(IdentityPrefix), data)
	if err != nil {
		return ""
	}
	return strings.ToUpper(encoded)
}

// Unwrap decrypts a file key using this identity.
// It finds the matching stanza and delegates ECDH to iOS.
func (i *Identity) Unwrap(stanzas []*age.Stanza) (fileKey []byte, err error) {
	ageLog.Debug("Unwrap called with %d stanzas", len(stanzas))

	// Find a stanza we can decrypt
	for idx, stanza := range stanzas {
		ageLog.Debug("Checking stanza %d: type=%s", idx, stanza.Type)
		if stanza.Type != StanzaType {
			continue
		}

		// Parse ephemeral public key from stanza args
		if len(stanza.Args) < 1 {
			ageLog.Debug("Stanza has no args, skipping")
			continue
		}

		ephemeralPublic, decErr := base64.RawStdEncoding.DecodeString(stanza.Args[0])
		if decErr != nil || len(ephemeralPublic) != 32 {
			ageLog.Debug("Invalid ephemeral public key: err=%v, len=%d", decErr, len(ephemeralPublic))
			continue
		}

		// The stanza body contains the wrapped file key
		wrappedKey := stanza.Body
		ageLog.Debug("Found matching stanza, wrapped key len=%d", len(wrappedKey))

		// Delegate to iOS for ECDH + unwrap
		if i.UnwrapFunc == nil {
			return nil, fmt.Errorf("no unwrap function configured")
		}

		ageLog.Debug("Calling UnwrapFunc...")
		fileKey, err = i.UnwrapFunc(ephemeralPublic, wrappedKey, i.PublicKey)
		if err != nil {
			ageLog.Debug("UnwrapFunc error: %v", err)
			// Try next stanza on error
			continue
		}

		ageLog.Debug("Unwrap successful!")
		return fileKey, nil
	}

	ageLog.Debug("No matching stanza found, returning ErrIncorrectIdentity")
	return nil, age.ErrIncorrectIdentity
}

// IdentityFromKey creates an Identity from a KeyMetadata
func IdentityFromKey(key *config.KeyMetadata, cfg *config.Config, unwrapFunc func(ephemeralPublic, wrappedKey, recipientPublic []byte) ([]byte, error)) *Identity {
	return &Identity{
		PublicKeyHex: key.Hex(),
		PublicKey:    key.PublicKey,
		Config:       cfg,
		UnwrapFunc:   unwrapFunc,
	}
}
