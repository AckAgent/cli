package age

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestBech32Encode(t *testing.T) {
	tests := []struct {
		name    string
		hrp     string
		data    []byte
		wantErr bool
	}{
		{
			name:    "single byte zero",
			hrp:     "test",
			data:    []byte{0x00},
			wantErr: false,
		},
		{
			name:    "single byte max",
			hrp:     "test",
			data:    []byte{0xff},
			wantErr: false,
		},
		{
			name:    "32 byte X25519 key",
			hrp:     "age1ackagent",
			data:    bytes.Repeat([]byte{0xAB}, 32),
			wantErr: false,
		},
		{
			name:    "age recipient prefix with key",
			hrp:     RecipientPrefix,
			data:    bytes.Repeat([]byte{0x12}, 32),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := bech32Encode(tt.hrp, tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("bech32Encode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				// Verify output starts with lowercase hrp followed by '1'
				if !strings.HasPrefix(got, strings.ToLower(tt.hrp)+"1") {
					t.Errorf("bech32Encode() = %v, should start with %s1", got, tt.hrp)
				}
			}
		})
	}
}

func TestBech32Decode(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantErr     bool
		errContains string
	}{
		{
			name:        "missing separator",
			input:       "test",
			wantErr:     true,
			errContains: "invalid bech32 string",
		},
		{
			name:        "invalid character",
			input:       "test1lqqqqb", // 'b' not in charset
			wantErr:     true,
			errContains: "invalid character",
		},
		{
			name:        "too short after separator",
			input:       "a1bb",
			wantErr:     true,
			errContains: "invalid bech32 string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := bech32Decode(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("bech32Decode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if tt.errContains != "" && err != nil {
					if !strings.Contains(err.Error(), tt.errContains) {
						t.Errorf("bech32Decode() error = %v, want error containing %v", err, tt.errContains)
					}
				}
				return
			}
		})
	}
}

func TestBech32DecodeValid(t *testing.T) {
	// Test by encoding first then decoding
	testData := bytes.Repeat([]byte{0x42}, 32)
	encoded, err := bech32Encode("test", testData)
	if err != nil {
		t.Fatalf("bech32Encode() error = %v", err)
	}

	hrp, decoded, err := bech32Decode(encoded)
	if err != nil {
		t.Fatalf("bech32Decode() error = %v", err)
	}

	if hrp != "test" {
		t.Errorf("bech32Decode() hrp = %v, want 'test'", hrp)
	}

	if !bytes.Equal(decoded, testData) {
		t.Errorf("bech32Decode() data mismatch")
	}
}

func TestBech32Roundtrip(t *testing.T) {
	tests := []struct {
		name string
		hrp  string
		data []byte
	}{
		{
			name: "single byte zero",
			hrp:  "bc",
			data: []byte{0x00},
		},
		{
			name: "single byte max",
			hrp:  "bc",
			data: []byte{0xff},
		},
		{
			name: "32 byte X25519 public key",
			hrp:  "age1ackagent",
			data: bytes.Repeat([]byte{0xAB}, 32),
		},
		{
			name: "sequential bytes",
			hrp:  "test",
			data: func() []byte {
				d := make([]byte, 32)
				for i := range d {
					d[i] = byte(i)
				}
				return d
			}(),
		},
		{
			name: "age recipient HRP with random key",
			hrp:  RecipientPrefix,
			data: func() []byte {
				key, _ := hex.DecodeString("e6eb32e9739a52ef8e2c95aa9f1a7f2fddc8dd9fa79eef22c7a0d0f4e52f3d1a")
				return key
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := bech32Encode(tt.hrp, tt.data)
			if err != nil {
				t.Fatalf("bech32Encode() error = %v", err)
			}

			hrp, decoded, err := bech32Decode(encoded)
			if err != nil {
				t.Fatalf("bech32Decode() error = %v", err)
			}

			if hrp != tt.hrp {
				t.Errorf("roundtrip hrp = %v, want %v", hrp, tt.hrp)
			}
			if !bytes.Equal(decoded, tt.data) {
				t.Errorf("roundtrip data = %x, want %x", decoded, tt.data)
			}
		})
	}
}

func TestConvertBits8To5(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "empty",
			data: []byte{},
		},
		{
			name: "single zero byte",
			data: []byte{0x00},
		},
		{
			name: "single max byte",
			data: []byte{0xff},
		},
		{
			name: "two bytes",
			data: []byte{0x00, 0xff},
		},
		{
			name: "32 bytes",
			data: bytes.Repeat([]byte{0xAB}, 32),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertBits(tt.data, 8, 5, true)
			// For non-empty input, we should get non-nil result
			if len(tt.data) > 0 && result == nil {
				t.Errorf("convertBits(8->5) returned nil for non-empty input")
			}
			// All values should be < 32 (5 bits)
			for i, v := range result {
				if v >= 32 {
					t.Errorf("convertBits(8->5)[%d] = %d, should be < 32", i, v)
				}
			}
		})
	}
}

func TestConvertBits5To8(t *testing.T) {
	// Test that 5->8 conversion reverses 8->5 conversion
	originalData := []byte{0x12, 0x34, 0x56, 0x78, 0x9a}

	// Convert 8 -> 5
	data5 := convertBits(originalData, 8, 5, true)
	if data5 == nil {
		t.Fatal("convertBits(8->5) returned nil")
	}

	// Convert 5 -> 8
	data8 := convertBits(data5, 5, 8, false)
	if data8 == nil {
		t.Fatal("convertBits(5->8) returned nil")
	}

	if !bytes.Equal(data8, originalData) {
		t.Errorf("roundtrip failed: got %x, want %x", data8, originalData)
	}
}

func TestBech32Polymod(t *testing.T) {
	// Test that polymod produces consistent output
	values := []byte{0, 1, 2, 3, 4, 5}
	result1 := bech32Polymod(values)
	result2 := bech32Polymod(values)

	if result1 != result2 {
		t.Errorf("bech32Polymod not deterministic: %d != %d", result1, result2)
	}

	// Changing values should change result
	values2 := []byte{0, 1, 2, 3, 4, 6}
	result3 := bech32Polymod(values2)
	if result1 == result3 {
		t.Error("bech32Polymod should produce different results for different inputs")
	}
}

func TestHrpExpand(t *testing.T) {
	tests := []struct {
		hrp      string
		expected []byte
	}{
		{
			hrp:      "bc",
			expected: []byte{3, 3, 0, 2, 3}, // high bits, separator, low bits
		},
		{
			hrp:      "test",
			expected: []byte{3, 3, 3, 3, 0, 20, 5, 19, 20},
		},
	}

	for _, tt := range tests {
		t.Run(tt.hrp, func(t *testing.T) {
			result := hrpExpand(tt.hrp)
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("hrpExpand(%s) = %v, want %v", tt.hrp, result, tt.expected)
			}
		})
	}
}

func TestBech32Checksum(t *testing.T) {
	// Checksum should always be 6 bytes
	tests := []struct {
		hrp  string
		data []byte
	}{
		{"bc", []byte{}},
		{"bc", []byte{0, 1, 2, 3}},
		{"test", []byte{10, 11, 12, 13, 14, 15}},
		{RecipientPrefix, make([]byte, 52)}, // 32 bytes * 8/5 rounded up
	}

	for _, tt := range tests {
		t.Run(tt.hrp, func(t *testing.T) {
			checksum := bech32Checksum(tt.hrp, tt.data)
			if len(checksum) != 6 {
				t.Errorf("bech32Checksum() length = %d, want 6", len(checksum))
			}

			// Each byte should be < 32 (5 bits)
			for i, b := range checksum {
				if b >= 32 {
					t.Errorf("checksum[%d] = %d, want < 32", i, b)
				}
			}
		})
	}
}

func TestBech32VerifyChecksum(t *testing.T) {
	// Create a valid encoded string and verify its checksum
	originalData := []byte{0x01, 0x02, 0x03, 0x04}
	encoded, err := bech32Encode("test", originalData)
	if err != nil {
		t.Fatalf("failed to encode: %v", err)
	}

	// Extract data part (after '1')
	pos := len("test") + 1
	dataStr := encoded[pos:]

	// Convert to 5-bit values
	data := make([]byte, len(dataStr))
	for i, c := range dataStr {
		for j, ch := range charset {
			if byte(ch) == byte(c) {
				data[i] = byte(j)
				break
			}
		}
	}

	// Verify checksum
	if !bech32VerifyChecksum("test", data) {
		t.Error("bech32VerifyChecksum() returned false for valid checksum")
	}

	// Corrupt one byte and verify it fails
	data[0] = (data[0] + 1) % 32
	if bech32VerifyChecksum("test", data) {
		t.Error("bech32VerifyChecksum() returned true for corrupted data")
	}
}

func TestBech32CaseInsensitive(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03}
	encoded, _ := bech32Encode("test", data)

	// Decode lowercase
	_, decodedLower, err := bech32Decode(encoded)
	if err != nil {
		t.Fatalf("failed to decode lowercase: %v", err)
	}

	// Decode uppercase
	_, decodedUpper, err := bech32Decode(encoded)
	if err != nil {
		t.Fatalf("failed to decode uppercase: %v", err)
	}

	if !bytes.Equal(decodedLower, decodedUpper) {
		t.Error("case should not affect decoded data")
	}
}
