package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	protocol "github.com/ackagent/api/go/protocol"
)

// ProtocolTestVectors matches the structure of data/protocol_test_vectors.json
type ProtocolTestVectors struct {
	Description string       `json:"description"`
	SSHSK       SSHSKVectors `json:"ssh_sk"`
	TestKey     TestKey      `json:"test_key"`
}

type SSHSKVectors struct {
	Description         string                    `json:"description"`
	MessageConstruction []MessageConstructionCase `json:"message_construction"`
	EnrollResponse      ResponseContract          `json:"enroll_response"`
	SignResponse        ResponseContract          `json:"sign_response"`
}

type MessageConstructionCase struct {
	Description           string `json:"description"`
	Application           string `json:"application"`
	ApplicationHashHex    string `json:"application_hash_hex"`
	DataHex               string `json:"data_hex"`
	DataHashHex           string `json:"data_hash_hex"`
	Flags                 uint8  `json:"flags"`
	Counter               uint32 `json:"counter"`
	ExpectedMessageHex    string `json:"expected_message_hex"`
	ExpectedMessageLength int    `json:"expected_message_length"`
}

type ResponseContract struct {
	Description    string            `json:"description"`
	RequiredFields []string          `json:"required_fields"`
	OptionalFields []string          `json:"optional_fields,omitempty"`
	Examples       []ResponseExample `json:"examples"`
}

type ResponseExample struct {
	Description string                 `json:"description"`
	JSON        map[string]interface{} `json:"json"`
}

type TestKey struct {
	Description              string `json:"description"`
	PrivateKeyDHex           string `json:"private_key_d_hex"`
	PublicKeyXHex            string `json:"public_key_x_hex"`
	PublicKeyYHex            string `json:"public_key_y_hex"`
	PublicKeyUncompressedHex string `json:"public_key_uncompressed_hex"`
}

func loadProtocolVectors(t *testing.T) *ProtocolTestVectors {
	t.Helper()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to get caller info")
	}

	// Navigate from sk-provider/ to data/
	root := filepath.Clean(filepath.Join(filepath.Dir(file), ".."))
	path := filepath.Join(root, "data", "protocol_test_vectors.json")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read protocol test vectors: %v", err)
	}

	var vectors ProtocolTestVectors
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("failed to parse protocol test vectors: %v", err)
	}

	return &vectors
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	if s == "" {
		return []byte{}
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("failed to decode hex %q: %v", s, err)
	}
	return b
}

// BuildSSHSKMessage constructs the SSH SK protocol message that gets signed.
// Format: SHA256(application) || flags || counter (big-endian) || SHA256(data)
func BuildSSHSKMessage(application string, data []byte, flags uint8, counter uint32) []byte {
	var msg bytes.Buffer

	// 1. SHA256(application) - 32 bytes
	appHash := sha256.Sum256([]byte(application))
	msg.Write(appHash[:])

	// 2. flags - 1 byte
	msg.WriteByte(flags)

	// 3. counter - 4 bytes big-endian
	binary.Write(&msg, binary.BigEndian, counter)

	// 4. SHA256(data) - 32 bytes
	dataHash := sha256.Sum256(data)
	msg.Write(dataHash[:])

	return msg.Bytes()
}

// TestSSHSKMessageConstruction verifies the SSH SK message format is correct.
// This test ensures both Go and iOS agree on the exact message format.
func TestSSHSKMessageConstruction(t *testing.T) {
	vectors := loadProtocolVectors(t)

	for _, tc := range vectors.SSHSK.MessageConstruction {
		t.Run(tc.Description, func(t *testing.T) {
			data := mustDecodeHex(t, tc.DataHex)
			msg := BuildSSHSKMessage(tc.Application, data, tc.Flags, tc.Counter)

			// Verify length is always 69 bytes (32 + 1 + 4 + 32)
			if len(msg) != 69 {
				t.Errorf("message length: got %d, want 69", len(msg))
			}

			if tc.ExpectedMessageLength != 0 && len(msg) != tc.ExpectedMessageLength {
				t.Errorf("message length mismatch: got %d, want %d", len(msg), tc.ExpectedMessageLength)
			}

			// Verify against expected message
			expectedMsg := mustDecodeHex(t, tc.ExpectedMessageHex)
			if !bytes.Equal(msg, expectedMsg) {
				t.Errorf("message mismatch:\ngot:  %s\nwant: %s", hex.EncodeToString(msg), tc.ExpectedMessageHex)
			}
		})
	}
}

// TestSSHSKMessageComponents verifies individual components of the message.
func TestSSHSKMessageComponents(t *testing.T) {
	vectors := loadProtocolVectors(t)

	for _, tc := range vectors.SSHSK.MessageConstruction {
		t.Run(tc.Description, func(t *testing.T) {
			// Verify application hash
			appHash := sha256.Sum256([]byte(tc.Application))
			expectedAppHash := mustDecodeHex(t, tc.ApplicationHashHex)
			if !bytes.Equal(appHash[:], expectedAppHash) {
				t.Errorf("application hash mismatch:\ngot:  %s\nwant: %s",
					hex.EncodeToString(appHash[:]), tc.ApplicationHashHex)
			}

			// Verify data hash
			data := mustDecodeHex(t, tc.DataHex)
			dataHash := sha256.Sum256(data)
			expectedDataHash := mustDecodeHex(t, tc.DataHashHex)
			if !bytes.Equal(dataHash[:], expectedDataHash) {
				t.Errorf("data hash mismatch:\ngot:  %s\nwant: %s",
					hex.EncodeToString(dataHash[:]), tc.DataHashHex)
			}
		})
	}
}

// TestEnrollResponseParsing verifies sk_provider can parse iOS EnrollResponse JSON.
func TestEnrollResponseParsing(t *testing.T) {
	vectors := loadProtocolVectors(t)

	for _, example := range vectors.SSHSK.EnrollResponse.Examples {
		t.Run(example.Description, func(t *testing.T) {
			// Marshal the example JSON
			jsonData, err := json.Marshal(example.JSON)
			if err != nil {
				t.Fatalf("failed to marshal example JSON: %v", err)
			}

			// Parse into protocol.EnrollResponse (the generated struct)
			var resp protocol.EnrollResponse
			if err := json.Unmarshal(jsonData, &resp); err != nil {
				t.Fatalf("failed to parse EnrollResponse: %v", err)
			}

			// Verify required fields
			if resp.Status != protocol.EnrollResponseStatusApproved {
				t.Errorf("status: got %q, want %q", resp.Status, protocol.EnrollResponseStatusApproved)
			}
			if resp.PublicKeyHex == nil || len(*resp.PublicKeyHex) != 130 {
				t.Errorf("publicKeyHex length: got %d, want 130 hex chars (65 bytes uncompressed P-256)", len(*resp.PublicKeyHex))
			}
			if resp.IosKeyId == nil || *resp.IosKeyId == "" {
				t.Error("ios_key_id is empty")
			}
		})
	}
}

// TestSignResponseParsing verifies sk_provider can parse iOS SSHSignResponse JSON.
func TestSignResponseParsing(t *testing.T) {
	vectors := loadProtocolVectors(t)

	for _, example := range vectors.SSHSK.SignResponse.Examples {
		t.Run(example.Description, func(t *testing.T) {
			// Marshal the example JSON
			jsonData, err := json.Marshal(example.JSON)
			if err != nil {
				t.Fatalf("failed to marshal example JSON: %v", err)
			}

			// Parse into protocol.SignatureResponse (the generated struct)
			var resp protocol.SignatureResponse
			if err := json.Unmarshal(jsonData, &resp); err != nil {
				t.Fatalf("failed to parse SignatureResponse: %v", err)
			}

			// Verify required fields
			if resp.RequestId == nil || *resp.RequestId == "" {
				t.Error("request_id is empty")
			}
			if resp.Status == nil || *resp.Status != protocol.Approved {
				t.Errorf("status: want %q", protocol.Approved)
			}
			if resp.Signature == nil || len(*resp.Signature) != 64 {
				t.Errorf("signature length: want 64")
			}
			if resp.Counter == nil || *resp.Counter == 0 {
				t.Error("counter is 0 (should be at least 1)")
			}
		})
	}
}

// TestEnrollResponseRoundtrip verifies encoding/decoding preserves all fields.
func TestEnrollResponseRoundtrip(t *testing.T) {
	iosKeyID := "test-key-id"
	publicKeyBytes := make([]byte, 64)
	signature := make([]byte, 64)

	// Fill with recognizable patterns
	for i := range publicKeyBytes {
		publicKeyBytes[i] = byte(i)
	}
	for i := range signature {
		signature[i] = byte(i + 100)
	}

	publicKeyHex := hex.EncodeToString(publicKeyBytes)
	original := protocol.EnrollResponse{
		Status:          protocol.EnrollResponseStatusApproved,
		PublicKeyHex:    &publicKeyHex,
		IosKeyId:        &iosKeyID,
		SubkeySignature: &signature,
	}

	// Encode
	jsonData, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	// Decode
	var decoded protocol.EnrollResponse
	if err := json.Unmarshal(jsonData, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	// Verify all fields
	if decoded.Status != original.Status {
		t.Errorf("Status mismatch: got %q, want %q", decoded.Status, original.Status)
	}
	if decoded.PublicKeyHex == nil || *decoded.PublicKeyHex != publicKeyHex {
		t.Error("PublicKeyHex mismatch")
	}
	if decoded.IosKeyId == nil || *decoded.IosKeyId != iosKeyID {
		t.Errorf("IosKeyId mismatch")
	}
}

// TestSignResponseRoundtrip verifies encoding/decoding preserves all fields.
func TestSignResponseRoundtrip(t *testing.T) {
	requestID := "550e8400-e29b-41d4-a716-446655440000"
	status := protocol.Approved
	signature := make([]byte, 64)
	var counter int32 = 42

	// Fill with recognizable pattern
	for i := range signature {
		signature[i] = byte(i)
	}

	original := protocol.SignatureResponse{
		RequestId: &requestID,
		Status:    &status,
		Signature: &signature,
		Counter:   &counter,
	}

	// Encode
	jsonData, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	// Decode
	var decoded protocol.SignatureResponse
	if err := json.Unmarshal(jsonData, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	// Verify all fields
	if decoded.RequestId == nil || *decoded.RequestId != requestID {
		t.Errorf("RequestID mismatch")
	}
	if decoded.Status == nil || *decoded.Status != status {
		t.Errorf("Status mismatch")
	}
	if decoded.Signature == nil || !bytes.Equal(*decoded.Signature, signature) {
		t.Error("Signature mismatch")
	}
	if decoded.Counter == nil || *decoded.Counter != counter {
		t.Errorf("Counter mismatch: got %d, want %d", *decoded.Counter, counter)
	}
}

// TestMessageLengthIsAlways69Bytes is a sanity check for the protocol.
func TestMessageLengthIsAlways69Bytes(t *testing.T) {
	testCases := []struct {
		application string
		data        []byte
		flags       uint8
		counter     uint32
	}{
		{"ssh:", nil, 1, 1},
		{"ssh:", []byte("hello"), 1, 1},
		{"ssh://github.com", []byte("data"), 5, 100},
		{"ssh://very-long-application-name.example.com", make([]byte, 1000), 255, 0xFFFFFFFF},
	}

	for _, tc := range testCases {
		msg := BuildSSHSKMessage(tc.application, tc.data, tc.flags, tc.counter)
		if len(msg) != 69 {
			t.Errorf("message for app=%q data_len=%d: got %d bytes, want 69",
				tc.application, len(tc.data), len(msg))
		}
	}
}
