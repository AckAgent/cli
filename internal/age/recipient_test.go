package age

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"io"
	"strings"
	"testing"

	"filippo.io/age/plugin"
)

func TestParseRecipient(t *testing.T) {
	// Create a valid recipient string for testing
	testKey, _ := hex.DecodeString("e6eb32e9739a52ef8e2c95aa9f1a7f2fddc8dd9fa79eef22c7a0d0f4e52f3d1a")
	validRecipient := &Recipient{PublicKey: testKey}
	validString := validRecipient.String()

	tests := []struct {
		name        string
		input       string
		wantErr     bool
		errContains string
		keyLen      int
	}{
		{
			name:    "valid recipient",
			input:   validString,
			wantErr: false,
			keyLen:  32,
		},
		{
			name:        "wrong prefix",
			input:       "age1wrong" + validString[len(RecipientPrefix):],
			wantErr:     true,
			errContains: "must start with",
		},
		{
			name:        "invalid bech32",
			input:       RecipientPrefix + "invalid!!!",
			wantErr:     true,
			errContains: "invalid",
		},
		{
			name:        "empty input",
			input:       "",
			wantErr:     true,
			errContains: "must start with",
		},
		{
			name:        "prefix only",
			input:       RecipientPrefix,
			wantErr:     true,
			errContains: "invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recipient, err := ParseRecipient(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRecipient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("ParseRecipient() error = %v, want error containing %v", err, tt.errContains)
				}
				return
			}
			if len(recipient.PublicKey) != tt.keyLen {
				t.Errorf("ParseRecipient() key length = %d, want %d", len(recipient.PublicKey), tt.keyLen)
			}
		})
	}
}

func TestRecipientString(t *testing.T) {
	tests := []struct {
		name       string
		publicKey  []byte
		wantPrefix string
	}{
		{
			name:       "32 byte key",
			publicKey:  bytes.Repeat([]byte{0xAB}, 32),
			wantPrefix: RecipientPrefix,
		},
		{
			name: "sequential bytes key",
			publicKey: func() []byte {
				k := make([]byte, 32)
				for i := range k {
					k[i] = byte(i)
				}
				return k
			}(),
			wantPrefix: RecipientPrefix,
		},
		{
			name: "real looking key",
			publicKey: func() []byte {
				k, _ := hex.DecodeString("e6eb32e9739a52ef8e2c95aa9f1a7f2fddc8dd9fa79eef22c7a0d0f4e52f3d1a")
				return k
			}(),
			wantPrefix: RecipientPrefix,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Recipient{PublicKey: tt.publicKey}
			s := r.String()

			if !strings.HasPrefix(s, tt.wantPrefix) {
				t.Errorf("Recipient.String() = %v, want prefix %v", s, tt.wantPrefix)
			}

			// Should be lowercase
			if s != strings.ToLower(s) {
				t.Errorf("Recipient.String() should be lowercase: %v", s)
			}
		})
	}
}

func TestRecipientRoundtrip(t *testing.T) {
	testKeys := [][]byte{
		bytes.Repeat([]byte{0x00}, 32),
		bytes.Repeat([]byte{0xFF}, 32),
		bytes.Repeat([]byte{0xAB}, 32),
		func() []byte {
			k := make([]byte, 32)
			for i := range k {
				k[i] = byte(i)
			}
			return k
		}(),
		func() []byte {
			k, _ := hex.DecodeString("e6eb32e9739a52ef8e2c95aa9f1a7f2fddc8dd9fa79eef22c7a0d0f4e52f3d1a")
			return k
		}(),
	}

	for i, key := range testKeys {
		t.Run(hex.EncodeToString(key[:4]), func(t *testing.T) {
			original := &Recipient{PublicKey: key}
			encoded := original.String()

			parsed, err := ParseRecipient(encoded)
			if err != nil {
				t.Fatalf("ParseRecipient() error = %v", err)
			}

			if !bytes.Equal(parsed.PublicKey, original.PublicKey) {
				t.Errorf("roundtrip %d failed: got %x, want %x", i, parsed.PublicKey, original.PublicKey)
			}
		})
	}
}

func TestRecipientWrap(t *testing.T) {
	// Use deterministic randomness for testing
	oldRandom := secureRandom
	defer func() { secureRandom = oldRandom }()

	// Use a deterministic reader that returns sequential bytes
	deterministicBytes := make([]byte, 256)
	for i := range deterministicBytes {
		deterministicBytes[i] = byte(i)
	}
	secureRandom = bytes.NewReader(deterministicBytes)

	testKey, _ := hex.DecodeString("e6eb32e9739a52ef8e2c95aa9f1a7f2fddc8dd9fa79eef22c7a0d0f4e52f3d1a")
	recipient := &Recipient{PublicKey: testKey}

	// Standard age file key is 16 bytes
	fileKey := bytes.Repeat([]byte{0x42}, 16)

	stanzas, err := recipient.Wrap(fileKey)
	if err != nil {
		t.Fatalf("Wrap() error = %v", err)
	}

	if len(stanzas) != 1 {
		t.Fatalf("Wrap() returned %d stanzas, want 1", len(stanzas))
	}

	stanza := stanzas[0]

	// Verify stanza type
	if stanza.Type != StanzaType {
		t.Errorf("stanza.Type = %v, want %v", stanza.Type, StanzaType)
	}

	// Verify stanza has ephemeral public key argument
	if len(stanza.Args) != 1 {
		t.Fatalf("stanza.Args length = %d, want 1", len(stanza.Args))
	}

	// Ephemeral public key should be base64 encoded
	ephemeralPublic, err := base64.RawStdEncoding.DecodeString(stanza.Args[0])
	if err != nil {
		t.Fatalf("failed to decode ephemeral public key: %v", err)
	}

	if len(ephemeralPublic) != 32 {
		t.Errorf("ephemeral public key length = %d, want 32", len(ephemeralPublic))
	}

	// Body should contain wrapped key (file key + poly1305 tag = 16 + 16 = 32 bytes)
	if len(stanza.Body) != 32 {
		t.Errorf("stanza.Body length = %d, want 32", len(stanza.Body))
	}
}

func TestRecipientWrapDifferentFileKeys(t *testing.T) {
	testKey, _ := hex.DecodeString("e6eb32e9739a52ef8e2c95aa9f1a7f2fddc8dd9fa79eef22c7a0d0f4e52f3d1a")
	recipient := &Recipient{PublicKey: testKey}

	fileKey1 := bytes.Repeat([]byte{0x11}, 16)
	fileKey2 := bytes.Repeat([]byte{0x22}, 16)

	stanzas1, err := recipient.Wrap(fileKey1)
	if err != nil {
		t.Fatalf("Wrap(fileKey1) error = %v", err)
	}

	stanzas2, err := recipient.Wrap(fileKey2)
	if err != nil {
		t.Fatalf("Wrap(fileKey2) error = %v", err)
	}

	// Different file keys should produce different wrapped bodies
	// (ephemeral keys are also different each time due to randomness)
	if bytes.Equal(stanzas1[0].Body, stanzas2[0].Body) {
		t.Error("different file keys should produce different wrapped bodies")
	}
}

func TestRecipientWrapRandomness(t *testing.T) {
	testKey, _ := hex.DecodeString("e6eb32e9739a52ef8e2c95aa9f1a7f2fddc8dd9fa79eef22c7a0d0f4e52f3d1a")
	recipient := &Recipient{PublicKey: testKey}

	fileKey := bytes.Repeat([]byte{0x42}, 16)

	stanzas1, _ := recipient.Wrap(fileKey)
	stanzas2, _ := recipient.Wrap(fileKey)

	// Same file key should produce different stanzas due to ephemeral key randomness
	if stanzas1[0].Args[0] == stanzas2[0].Args[0] {
		t.Error("ephemeral public keys should be different for each wrap")
	}
}

func TestRecipientWrapReadError(t *testing.T) {
	// Test that Wrap handles read errors gracefully
	oldRandom := secureRandom
	defer func() { secureRandom = oldRandom }()

	// Use an empty reader that will return EOF immediately
	secureRandom = bytes.NewReader([]byte{})

	testKey, _ := hex.DecodeString("e6eb32e9739a52ef8e2c95aa9f1a7f2fddc8dd9fa79eef22c7a0d0f4e52f3d1a")
	recipient := &Recipient{PublicKey: testKey}
	fileKey := bytes.Repeat([]byte{0x42}, 16)

	_, err := recipient.Wrap(fileKey)
	if err == nil {
		t.Error("Wrap() should fail when randomness source is exhausted")
	}
}

func TestDeriveKey(t *testing.T) {
	sharedSecret := bytes.Repeat([]byte{0xAB}, 32)
	salt := bytes.Repeat([]byte{0xCD}, 64)

	key, err := deriveKey(sharedSecret, salt)
	if err != nil {
		t.Fatalf("deriveKey() error = %v", err)
	}

	// Key should be 32 bytes (ChaCha20-Poly1305 key size)
	if len(key) != 32 {
		t.Errorf("deriveKey() length = %d, want 32", len(key))
	}

	// Same inputs should produce same output (deterministic)
	key2, _ := deriveKey(sharedSecret, salt)
	if !bytes.Equal(key, key2) {
		t.Error("deriveKey() should be deterministic")
	}

	// Different inputs should produce different outputs
	differentSecret := bytes.Repeat([]byte{0xEF}, 32)
	key3, _ := deriveKey(differentSecret, salt)
	if bytes.Equal(key, key3) {
		t.Error("deriveKey() should produce different keys for different secrets")
	}
}

func TestDeriveKeyWithLabel(t *testing.T) {
	// Verify the HKDF label is being used correctly
	// The hkdfLabel constant should match age's X25519 label
	if hkdfLabel != "age-encryption.org/v1/X25519" {
		t.Errorf("hkdfLabel = %v, want age-encryption.org/v1/X25519", hkdfLabel)
	}
}

// mockRandomReader provides controlled randomness for testing
type mockRandomReader struct {
	data   []byte
	offset int
}

func (m *mockRandomReader) Read(p []byte) (n int, err error) {
	if m.offset >= len(m.data) {
		return 0, io.EOF
	}
	n = copy(p, m.data[m.offset:])
	m.offset += n
	return n, nil
}

func TestRecipientPluginFrameworkCompatibility(t *testing.T) {
	// This test verifies our recipient encoding is compatible with the
	// filippo.io/age/plugin framework that the age CLI uses

	testCases := []struct {
		name      string
		publicKey []byte
	}{
		{"32 byte key", bytes.Repeat([]byte{0x42}, 32)},
		{"random key", func() []byte {
			key, _ := hex.DecodeString("e6eb32e9739a52ef8e2c95aa9f1a7f2fddc8dd9fa79eef22c7a0d0f4e52f3d1a")
			return key
		}()},
		{"all zeros", make([]byte, 32)},
		{"all ones", bytes.Repeat([]byte{0xFF}, 32)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create recipient using our implementation
			recipient := &Recipient{PublicKey: tc.publicKey}
			ourEncoding := recipient.String()

			t.Logf("Our encoding: %s", ourEncoding)

			// Create the same recipient using the plugin framework
			pluginEncoding := plugin.EncodeRecipient("ackagent", tc.publicKey)

			t.Logf("Plugin framework encoding: %s", pluginEncoding)

			// They should match exactly
			if ourEncoding != pluginEncoding {
				t.Errorf("Encoding mismatch:\n  Ours:   %s\n  Plugin: %s", ourEncoding, pluginEncoding)
			}

			// Verify the plugin framework can parse our encoding
			name, data, err := plugin.ParseRecipient(ourEncoding)
			if err != nil {
				t.Errorf("plugin.ParseRecipient(%v) failed: %v", ourEncoding, err)
				return
			}

			if name != "ackagent" {
				t.Errorf("Parsed plugin name = %v, want ackagent", name)
			}

			if !bytes.Equal(data, tc.publicKey) {
				t.Errorf("Parsed public key doesn't match original")
			}

			// Also verify our own parsing works
			parsed, err := ParseRecipient(ourEncoding)
			if err != nil {
				t.Errorf("ParseRecipient(%v) failed: %v", ourEncoding, err)
				return
			}

			if !bytes.Equal(parsed.PublicKey, tc.publicKey) {
				t.Errorf("Roundtrip public key doesn't match original")
			}
		})
	}
}
