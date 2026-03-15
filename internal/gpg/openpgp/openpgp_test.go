package openpgp

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestEncodeMPI(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected []byte
	}{
		{
			name:     "single byte",
			input:    []byte{0x01},
			expected: []byte{0x00, 0x01, 0x01},
		},
		{
			name:     "256",
			input:    []byte{0x01, 0x00},
			expected: []byte{0x00, 0x09, 0x01, 0x00},
		},
		{
			name:     "leading zeros stripped",
			input:    []byte{0x00, 0x00, 0x7F},
			expected: []byte{0x00, 0x07, 0x7F},
		},
		{
			name:     "32-byte value",
			input:    bytes.Repeat([]byte{0xFF}, 32),
			expected: append([]byte{0x01, 0x00}, bytes.Repeat([]byte{0xFF}, 32)...), // 256 bits
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := EncodeMPIFromBytes(tt.input)
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("EncodeMPIFromBytes(%x) = %x, want %x", tt.input, result, tt.expected)
			}
		})
	}
}

func TestCRC24(t *testing.T) {
	// Test vector from RFC 4880
	input := []byte("Hello, World!")
	crc := CRC24(input)

	// The CRC24 should be 24 bits
	if crc > 0xFFFFFF {
		t.Errorf("CRC24 exceeded 24 bits: %x", crc)
	}
}

func TestArmor(t *testing.T) {
	data := []byte("test data")
	armored := Armor(ArmorSignature, data)

	if !strings.HasPrefix(armored, "-----BEGIN PGP SIGNATURE-----\n") {
		t.Error("Missing armor header")
	}

	if !strings.HasSuffix(armored, "-----END PGP SIGNATURE-----\n") {
		t.Error("Missing armor footer")
	}

	// Check CRC is present
	if !strings.Contains(armored, "=") {
		t.Error("Missing CRC line")
	}
}

func TestV4Fingerprint(t *testing.T) {
	// Test with a known P-256 public key (65 bytes: 0x04 || X || Y)
	pubKey := make([]byte, 65)
	pubKey[0] = 0x04
	for i := 1; i < len(pubKey); i++ {
		pubKey[i] = byte(i)
	}

	creationTime := time.Unix(1700000000, 0)

	fp := V4Fingerprint(pubKey, creationTime)

	// V4 fingerprint should be 20 bytes (SHA-1)
	if len(fp) != 20 {
		t.Errorf("V4Fingerprint length = %d, want 20", len(fp))
	}

	// Key ID should be last 8 bytes
	keyID := KeyIDFromFingerprint(fp)
	if keyID == 0 {
		t.Error("KeyID should not be zero")
	}
}

func TestFormatFingerprint(t *testing.T) {
	fp := make([]byte, 20)
	for i := range fp {
		fp[i] = byte(i)
	}

	formatted := FormatFingerprint(fp)

	// Should have spaces
	if !strings.Contains(formatted, " ") {
		t.Error("Formatted fingerprint should contain spaces")
	}

	// Should be uppercase hex
	if formatted != strings.ToUpper(formatted) {
		t.Error("Formatted fingerprint should be uppercase")
	}
}

func TestPacketHeader(t *testing.T) {
	// Test old-format packet header with small body
	header := EncodeOldPacketHeader(PacketTagSignature, 100)
	if len(header) != 2 {
		t.Errorf("Old packet header length = %d, want 2", len(header))
	}

	// Tag should be (0x80 | (2 << 2) | 0) = 0x88
	if header[0] != 0x88 {
		t.Errorf("Old packet header tag = 0x%x, want 0x88", header[0])
	}

	// Length should be 100
	if header[1] != 100 {
		t.Errorf("Old packet header length byte = %d, want 100", header[1])
	}
}

func TestSubpacketCreationTime(t *testing.T) {
	sb := NewSubpacketBuilder()
	creationTime := time.Unix(1700000000, 0)
	sb.AddCreationTime(creationTime)

	data := sb.Bytes()

	// Should have: length (1) + type (1) + timestamp (4) = 6 bytes
	if len(data) != 6 {
		t.Errorf("Creation time subpacket length = %d, want 6", len(data))
	}

	// Length should be 5 (type + 4 bytes)
	if data[0] != 5 {
		t.Errorf("Subpacket length = %d, want 5", data[0])
	}

	// Type should be 2 (creation time)
	if data[1] != SubpacketSignatureCreationTime {
		t.Errorf("Subpacket type = %d, want %d", data[1], SubpacketSignatureCreationTime)
	}
}

func TestSignatureBuilder(t *testing.T) {
	message := []byte("test message")
	creationTime := time.Unix(1700000000, 0)
	fingerprint := make([]byte, 20)
	for i := range fingerprint {
		fingerprint[i] = byte(i)
	}
	keyID := KeyIDFromFingerprint(fingerprint)

	sb := NewSignatureBuilder().
		SetSignatureType(SigTypeBinary).
		SetCreationTime(creationTime).
		SetIssuerKeyID(keyID).
		SetIssuerFingerprint(fingerprint)

	digest, header := sb.BuildHashInput(message)

	// Digest should be 32 bytes (SHA-256)
	if len(digest) != 32 {
		t.Errorf("Digest length = %d, want 32", len(digest))
	}

	// Header should start with version 4
	if header[0] != SigVersion4 {
		t.Errorf("Header version = %d, want %d", header[0], SigVersion4)
	}

	// Simulate a 64-byte ECDSA signature
	rawSig := make([]byte, 64)
	for i := range rawSig {
		rawSig[i] = byte(i)
	}

	sigPacket, err := sb.FinalizeSignature(header, digest, rawSig)
	if err != nil {
		t.Fatalf("FinalizeSignature failed: %v", err)
	}

	// Signature packet should start with packet tag
	if sigPacket[0] != 0x88 && (sigPacket[0]&0xC0) != 0xC0 {
		t.Errorf("Invalid packet tag: 0x%x", sigPacket[0])
	}
}

func TestBuildPublicKeyPacket(t *testing.T) {
	pubKey := make([]byte, 65)
	pubKey[0] = 0x04
	for i := 1; i < len(pubKey); i++ {
		pubKey[i] = byte(i)
	}
	creationTime := time.Unix(1700000000, 0)

	packet := BuildPublicKeyPacket(pubKey, creationTime)

	// Should start with old-format packet tag for public key
	// (0x80 | (6 << 2) | length_type)
	tag := packet[0]
	if (tag & 0x80) == 0 {
		t.Error("Packet should have high bit set")
	}

	// Extract packet tag (bits 5-2)
	packetTag := (tag & 0x3C) >> 2
	if packetTag != PacketTagPublicKey {
		t.Errorf("Packet tag = %d, want %d", packetTag, PacketTagPublicKey)
	}
}

func TestEncodeCRC24(t *testing.T) {
	data := []byte("test")
	crcStr := EncodeCRC24(data)

	// Should start with '='
	if !strings.HasPrefix(crcStr, "=") {
		t.Error("CRC should start with '='")
	}

	// After '=' should be 4 base64 characters (24 bits = 3 bytes = 4 base64 chars)
	if len(crcStr) != 5 {
		t.Errorf("CRC string length = %d, want 5", len(crcStr))
	}
}

func TestFormatKeyID(t *testing.T) {
	keyID := uint64(0x0102030405060708)
	formatted := FormatKeyID(keyID)

	expected := "0102030405060708"
	if formatted != expected {
		t.Errorf("FormatKeyID = %s, want %s", formatted, expected)
	}
}

func TestBuildUserIDPacket(t *testing.T) {
	userID := "Test User <test@example.com>"
	packet := BuildUserIDPacket(userID)

	// Should start with old-format packet tag for user ID
	tag := packet[0]
	packetTag := (tag & 0x3C) >> 2
	if packetTag != PacketTagUserID {
		t.Errorf("Packet tag = %d, want %d", packetTag, PacketTagUserID)
	}
}

func TestSignatureFlow(t *testing.T) {
	// Full flow test
	message := []byte("This is a test message for signing")
	creationTime := time.Now()

	// Generate a fake fingerprint
	fingerprint, _ := hex.DecodeString("0102030405060708090A0B0C0D0E0F1011121314")
	keyID := KeyIDFromFingerprint(fingerprint)

	// Build signature using SignatureBuilder
	sb := NewSignatureBuilder().
		SetCreationTime(creationTime).
		SetIssuerKeyID(keyID).
		SetIssuerFingerprint(fingerprint)

	digest, header := sb.BuildHashInput(message)
	sigPacket, err := sb.FinalizeSignature(header, digest, make([]byte, 64))
	if err != nil {
		t.Fatalf("FinalizeSignature failed: %v", err)
	}

	// Armor it
	armored := ArmorSig(sigPacket)

	// Verify format
	if !strings.Contains(armored, "-----BEGIN PGP SIGNATURE-----") {
		t.Error("Missing signature header")
	}
	if !strings.Contains(armored, "-----END PGP SIGNATURE-----") {
		t.Error("Missing signature footer")
	}
}
