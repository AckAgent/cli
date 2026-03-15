package age

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"github.com/ackagent/cli/internal/shared/config"
)

func TestParseIdentity(t *testing.T) {
	// Create a valid identity string for testing
	testFingerprint := "age:ABCD1234567890"
	validIdentity := &Identity{PublicKeyHex: testFingerprint}
	validString := validIdentity.String()

	tests := []struct {
		name        string
		input       string
		wantErr     bool
		errContains string
	}{
		{
			name:    "valid identity",
			input:   validString,
			wantErr: false,
		},
		{
			name:        "wrong prefix",
			input:       "AGE-PLUGIN-WRONG-" + validString[len(IdentityPrefix):],
			wantErr:     true,
			errContains: "must start with",
		},
		{
			name:        "empty input",
			input:       "",
			wantErr:     true,
			errContains: "must start with",
		},
		{
			name:        "prefix only",
			input:       IdentityPrefix,
			wantErr:     true,
			errContains: "invalid",
		},
		{
			name:    "lowercase valid identity",
			input:   strings.ToLower(validString),
			wantErr: false, // Should be case-insensitive
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity, err := ParseIdentity(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseIdentity() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("ParseIdentity() error = %v, want error containing %v", err, tt.errContains)
				}
				return
			}
			if identity == nil {
				t.Error("ParseIdentity() returned nil identity")
			}
		})
	}
}

func TestIdentityString(t *testing.T) {
	tests := []struct {
		name        string
		fingerprint string
	}{
		{
			name:        "standard fingerprint",
			fingerprint: "age:ABCD1234567890",
		},
		{
			name:        "short fingerprint",
			fingerprint: "age:AB12",
		},
		{
			name:        "long fingerprint",
			fingerprint: "age:ABCDEFGHIJKLMNOP1234567890abcdefg",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity := &Identity{PublicKeyHex: tt.fingerprint}
			s := identity.String()

			// Should start with uppercase prefix
			if !strings.HasPrefix(s, IdentityPrefix) {
				t.Errorf("Identity.String() = %v, want prefix %v", s, IdentityPrefix)
			}

			// Should be uppercase (identity format requirement)
			if s != strings.ToUpper(s) {
				t.Errorf("Identity.String() should be uppercase: %v", s)
			}
		})
	}
}

func TestIdentityRoundtrip(t *testing.T) {
	fingerprints := []string{
		"age:ABCD1234567890",
		"age:12345678",
		"age:abcdefghijklmnop",
		"test-fingerprint",
		"gpg-style-fp:ABC123",
	}

	for _, fp := range fingerprints {
		t.Run(fp, func(t *testing.T) {
			original := &Identity{PublicKeyHex: fp}
			encoded := original.String()

			parsed, err := ParseIdentity(encoded)
			if err != nil {
				t.Fatalf("ParseIdentity() error = %v", err)
			}

			if parsed.PublicKeyHex != original.PublicKeyHex {
				t.Errorf("roundtrip failed: got %q, want %q", parsed.PublicKeyHex, original.PublicKeyHex)
			}
		})
	}
}

func TestIdentityUnwrap(t *testing.T) {
	testPublicKey, _ := hex.DecodeString("e6eb32e9739a52ef8e2c95aa9f1a7f2fddc8dd9fa79eef22c7a0d0f4e52f3d1a")
	ephemeralPublic, _ := hex.DecodeString("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
	expectedFileKey := bytes.Repeat([]byte{0x42}, 16)

	tests := []struct {
		name        string
		stanzas     []*age.Stanza
		unwrapFunc  func(ephemeralPublic, wrappedKey, recipientPublic []byte) ([]byte, error)
		wantErr     bool
		errContains string
		wantFileKey []byte
	}{
		{
			name: "successful unwrap",
			stanzas: []*age.Stanza{
				{
					Type: StanzaType,
					Args: []string{base64.RawStdEncoding.EncodeToString(ephemeralPublic)},
					Body: bytes.Repeat([]byte{0xAB}, 32), // wrapped file key
				},
			},
			unwrapFunc: func(ep, wk, rp []byte) ([]byte, error) {
				return expectedFileKey, nil
			},
			wantErr:     false,
			wantFileKey: expectedFileKey,
		},
		{
			name: "no matching stanza type",
			stanzas: []*age.Stanza{
				{
					Type: "X25519", // standard age type, not ackagent
					Args: []string{base64.RawStdEncoding.EncodeToString(ephemeralPublic)},
					Body: bytes.Repeat([]byte{0xAB}, 32),
				},
			},
			unwrapFunc: func(ep, wk, rp []byte) ([]byte, error) {
				return expectedFileKey, nil
			},
			wantErr:     true,
			errContains: "", // Returns age.ErrIncorrectIdentity
		},
		{
			name:        "empty stanzas",
			stanzas:     []*age.Stanza{},
			wantErr:     true,
			errContains: "",
		},
		{
			name: "missing ephemeral key argument",
			stanzas: []*age.Stanza{
				{
					Type: StanzaType,
					Args: []string{}, // no args
					Body: bytes.Repeat([]byte{0xAB}, 32),
				},
			},
			unwrapFunc: func(ep, wk, rp []byte) ([]byte, error) {
				return expectedFileKey, nil
			},
			wantErr: true,
		},
		{
			name: "invalid base64 ephemeral key",
			stanzas: []*age.Stanza{
				{
					Type: StanzaType,
					Args: []string{"not-valid-base64!!!"},
					Body: bytes.Repeat([]byte{0xAB}, 32),
				},
			},
			unwrapFunc: func(ep, wk, rp []byte) ([]byte, error) {
				return expectedFileKey, nil
			},
			wantErr: true,
		},
		{
			name: "ephemeral key wrong length",
			stanzas: []*age.Stanza{
				{
					Type: StanzaType,
					Args: []string{base64.RawStdEncoding.EncodeToString([]byte{0x01, 0x02})}, // only 2 bytes
					Body: bytes.Repeat([]byte{0xAB}, 32),
				},
			},
			unwrapFunc: func(ep, wk, rp []byte) ([]byte, error) {
				return expectedFileKey, nil
			},
			wantErr: true,
		},
		{
			name: "nil unwrap func",
			stanzas: []*age.Stanza{
				{
					Type: StanzaType,
					Args: []string{base64.RawStdEncoding.EncodeToString(ephemeralPublic)},
					Body: bytes.Repeat([]byte{0xAB}, 32),
				},
			},
			unwrapFunc:  nil,
			wantErr:     true,
			errContains: "no unwrap function",
		},
		{
			name: "unwrap func returns error",
			stanzas: []*age.Stanza{
				{
					Type: StanzaType,
					Args: []string{base64.RawStdEncoding.EncodeToString(ephemeralPublic)},
					Body: bytes.Repeat([]byte{0xAB}, 32),
				},
			},
			unwrapFunc: func(ep, wk, rp []byte) ([]byte, error) {
				return nil, errors.New("iOS declined")
			},
			wantErr: true, // Falls through to ErrIncorrectIdentity
		},
		{
			name: "multiple stanzas - first fails, second succeeds",
			stanzas: []*age.Stanza{
				{
					Type: StanzaType,
					Args: []string{base64.RawStdEncoding.EncodeToString(ephemeralPublic)},
					Body: bytes.Repeat([]byte{0xAA}, 32),
				},
				{
					Type: StanzaType,
					Args: []string{base64.RawStdEncoding.EncodeToString(ephemeralPublic)},
					Body: bytes.Repeat([]byte{0xBB}, 32),
				},
			},
			unwrapFunc: func() func(ep, wk, rp []byte) ([]byte, error) {
				calls := 0
				return func(ep, wk, rp []byte) ([]byte, error) {
					calls++
					if calls == 1 {
						return nil, errors.New("first stanza failed")
					}
					return expectedFileKey, nil
				}
			}(),
			wantErr:     false,
			wantFileKey: expectedFileKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity := &Identity{
				PublicKeyHex: "test-fingerprint",
				PublicKey:    testPublicKey,
				UnwrapFunc:   tt.unwrapFunc,
			}

			fileKey, err := identity.Unwrap(tt.stanzas)
			if (err != nil) != tt.wantErr {
				t.Errorf("Unwrap() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("Unwrap() error = %v, want error containing %v", err, tt.errContains)
				}
				return
			}

			if !bytes.Equal(fileKey, tt.wantFileKey) {
				t.Errorf("Unwrap() fileKey = %x, want %x", fileKey, tt.wantFileKey)
			}
		})
	}
}

func TestIdentityUnwrapCallsUnwrapFunc(t *testing.T) {
	testPublicKey, _ := hex.DecodeString("e6eb32e9739a52ef8e2c95aa9f1a7f2fddc8dd9fa79eef22c7a0d0f4e52f3d1a")
	ephemeralPublic, _ := hex.DecodeString("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
	wrappedKey := bytes.Repeat([]byte{0xAB}, 32)

	var capturedEphemeral, capturedWrapped, capturedRecipient []byte

	identity := &Identity{
		PublicKeyHex: "test-fingerprint",
		PublicKey:    testPublicKey,
		UnwrapFunc: func(ep, wk, rp []byte) ([]byte, error) {
			capturedEphemeral = ep
			capturedWrapped = wk
			capturedRecipient = rp
			return bytes.Repeat([]byte{0x42}, 16), nil
		},
	}

	stanzas := []*age.Stanza{
		{
			Type: StanzaType,
			Args: []string{base64.RawStdEncoding.EncodeToString(ephemeralPublic)},
			Body: wrappedKey,
		},
	}

	_, err := identity.Unwrap(stanzas)
	if err != nil {
		t.Fatalf("Unwrap() error = %v", err)
	}

	// Verify the UnwrapFunc received correct arguments
	if !bytes.Equal(capturedEphemeral, ephemeralPublic) {
		t.Errorf("UnwrapFunc received ephemeral = %x, want %x", capturedEphemeral, ephemeralPublic)
	}

	if !bytes.Equal(capturedWrapped, wrappedKey) {
		t.Errorf("UnwrapFunc received wrapped = %x, want %x", capturedWrapped, wrappedKey)
	}

	if !bytes.Equal(capturedRecipient, testPublicKey) {
		t.Errorf("UnwrapFunc received recipient = %x, want %x", capturedRecipient, testPublicKey)
	}
}

func TestIdentityFromKey(t *testing.T) {
	testPublicKey, _ := hex.DecodeString("e6eb32e9739a52ef8e2c95aa9f1a7f2fddc8dd9fa79eef22c7a0d0f4e52f3d1a")

	key := &config.KeyMetadata{
		PublicKey: testPublicKey,
		Purpose:   config.KeyPurposeAge,
	}

	cfg := &config.Config{}

	unwrapCalled := false
	unwrapFunc := func(ep, wk, rp []byte) ([]byte, error) {
		unwrapCalled = true
		return nil, nil
	}

	identity := IdentityFromKey(key, cfg, unwrapFunc)

	// Verify fields are set correctly
	if identity.PublicKeyHex != key.Hex() {
		t.Errorf("IdentityFromKey().PublicKeyHex = %v, want %v", identity.PublicKeyHex, key.Hex())
	}

	if !bytes.Equal(identity.PublicKey, key.PublicKey) {
		t.Errorf("IdentityFromKey().PublicKey = %x, want %x", identity.PublicKey, key.PublicKey)
	}

	if identity.Config != cfg {
		t.Error("IdentityFromKey().Config should reference the provided config")
	}

	// Verify UnwrapFunc is set
	if identity.UnwrapFunc == nil {
		t.Error("IdentityFromKey().UnwrapFunc should not be nil")
	}

	// Verify UnwrapFunc is callable
	identity.UnwrapFunc(nil, nil, nil)
	if !unwrapCalled {
		t.Error("UnwrapFunc was not called")
	}
}

func TestIdentityImplementsAgeIdentity(t *testing.T) {
	// Compile-time check that Identity implements age.Identity
	var _ age.Identity = (*Identity)(nil)
}

func TestIdentityPrefixConstant(t *testing.T) {
	// Verify the identity prefix follows age plugin convention
	if !strings.HasPrefix(IdentityPrefix, "AGE-PLUGIN-") {
		t.Errorf("IdentityPrefix = %v, should start with AGE-PLUGIN-", IdentityPrefix)
	}

	// Should be uppercase
	if IdentityPrefix != strings.ToUpper(IdentityPrefix) {
		t.Errorf("IdentityPrefix should be uppercase: %v", IdentityPrefix)
	}
}

func TestIdentityPluginFrameworkCompatibility(t *testing.T) {
	// This test verifies our identity encoding is compatible with the
	// filippo.io/age/plugin framework that the age CLI uses

	testCases := []struct {
		name        string
		fingerprint string
	}{
		{"simple fingerprint", "test-fp"},
		{"fingerprint with colons", "3f:ec:ed:65:52:46:c2:bb:5d:4f:ce:54:be:de:d0:f9"},
		{"age prefix", "age:ABCD1234567890"},
		{"long fingerprint", "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6"},
		{"fingerprint with slash", "age:ABC/DEF+GHI123"},
		{"fingerprint with plus", "age:++++++++++++++++"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create identity using our implementation
			identity := &Identity{PublicKeyHex: tc.fingerprint}
			ourEncoding := identity.String()

			t.Logf("Our encoding: %s", ourEncoding)

			// Create the same identity using the plugin framework
			pluginEncoding := plugin.EncodeIdentity("ackagent", []byte(tc.fingerprint))

			t.Logf("Plugin framework encoding: %s", pluginEncoding)

			// They should match exactly
			if ourEncoding != pluginEncoding {
				t.Errorf("Encoding mismatch:\n  Ours:   %s\n  Plugin: %s", ourEncoding, pluginEncoding)
			}

			// Verify the plugin framework can parse our encoding
			name, data, err := plugin.ParseIdentity(ourEncoding)
			if err != nil {
				t.Errorf("plugin.ParseIdentity(%v) failed: %v", ourEncoding, err)
				return
			}

			if name != "ackagent" {
				t.Errorf("Parsed plugin name = %v, want ackagent", name)
			}

			if string(data) != tc.fingerprint {
				t.Errorf("Parsed fingerprint = %v, want %v", string(data), tc.fingerprint)
			}

			// Also verify our own parsing works
			parsed, err := ParseIdentity(ourEncoding)
			if err != nil {
				t.Errorf("ParseIdentity(%v) failed: %v", ourEncoding, err)
				return
			}

			if parsed.PublicKeyHex != tc.fingerprint {
				t.Errorf("Roundtrip fingerprint = %v, want %v", parsed.PublicKeyHex, tc.fingerprint)
			}
		})
	}
}
