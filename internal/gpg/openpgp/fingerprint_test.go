package openpgp

import (
	"encoding/hex"
	"testing"
	"time"
)

func TestFormatFingerprintHex(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"AABBCCDDEEFF00112233", "AABB CCDD EEFF 0011 2233"},
		{"aabbccddeeff00112233", "AABB CCDD EEFF 0011 2233"},
		{"ABCD", "ABCD"},
		{"AB", "AB"},
		{"", ""},
		{"AABBCCDDEE", "AABB CCDD EE"},
	}

	for _, tt := range tests {
		got := FormatFingerprintHex(tt.input)
		if got != tt.want {
			t.Errorf("FormatFingerprintHex(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestParseFingerprint(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantHex string
		wantNil bool
	}{
		{"plain hex", "AABBCCDDEEFF", "aabbccddeeff", false},
		{"with spaces", "AABB CCDD EEFF", "aabbccddeeff", false},
		{"full 40-char fingerprint", "AABB CCDD EEFF 0011 2233 4455 6677 8899 AABB CCDD", "aabbccddeeff00112233445566778899aabbccdd", false},
		{"invalid hex", "GGHHII", "", true},
		{"empty", "", "", false}, // empty hex decodes to empty bytes
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseFingerprint(tt.input)
			if tt.wantNil {
				if got != nil {
					t.Errorf("ParseFingerprint(%q) = %x, want nil", tt.input, got)
				}
				return
			}
			if hex.EncodeToString(got) != tt.wantHex {
				t.Errorf("ParseFingerprint(%q) = %x, want %s", tt.input, got, tt.wantHex)
			}
		})
	}
}

func TestBuildPublicKeyPacketEd25519(t *testing.T) {
	pubKey := make([]byte, 32)
	for i := range pubKey {
		pubKey[i] = byte(i)
	}
	creationTime := time.Unix(1700000000, 0)

	packet := BuildPublicKeyPacketEd25519(pubKey, creationTime)
	if len(packet) == 0 {
		t.Fatal("BuildPublicKeyPacketEd25519 returned empty packet")
	}

	// Parse the packet to verify structure
	reader := NewPacketReader(packet)
	parsed, err := reader.Next()
	if err != nil {
		t.Fatalf("Failed to parse built packet: %v", err)
	}

	if parsed.Tag != PacketTagPublicKey {
		t.Errorf("expected tag %d, got %d", PacketTagPublicKey, parsed.Tag)
	}

	// Verify body starts with version 4
	if parsed.Body[0] != 4 {
		t.Errorf("expected version 4, got %d", parsed.Body[0])
	}
}

func TestV4FingerprintEd25519_Deterministic(t *testing.T) {
	pubKey := make([]byte, 32)
	for i := range pubKey {
		pubKey[i] = byte(i + 10)
	}
	creationTime := time.Unix(1700000000, 0)

	fp1 := V4FingerprintEd25519(pubKey, creationTime)
	fp2 := V4FingerprintEd25519(pubKey, creationTime)

	if len(fp1) != 20 {
		t.Errorf("fingerprint should be 20 bytes, got %d", len(fp1))
	}
	if hex.EncodeToString(fp1) != hex.EncodeToString(fp2) {
		t.Error("fingerprint should be deterministic")
	}

	// Different key → different fingerprint
	pubKey2 := make([]byte, 32)
	fp3 := V4FingerprintEd25519(pubKey2, creationTime)
	if hex.EncodeToString(fp1) == hex.EncodeToString(fp3) {
		t.Error("different keys should produce different fingerprints")
	}
}

func TestKeyIDFromFingerprint_ShortInput(t *testing.T) {
	// Less than 8 bytes
	got := KeyIDFromFingerprint([]byte{0x01, 0x02})
	if got != 0 {
		t.Errorf("expected 0 for short input, got %d", got)
	}

	// Empty
	got = KeyIDFromFingerprint(nil)
	if got != 0 {
		t.Errorf("expected 0 for nil input, got %d", got)
	}
}

func TestPacketWriterLen(t *testing.T) {
	pw := NewPacketWriter()
	if pw.Len() != 0 {
		t.Errorf("new PacketWriter.Len() = %d, want 0", pw.Len())
	}

	pw.WriteByte(0x01)
	if pw.Len() != 1 {
		t.Errorf("after WriteByte, PacketWriter.Len() = %d, want 1", pw.Len())
	}

	pw.Write([]byte{0x02, 0x03})
	if pw.Len() != 3 {
		t.Errorf("after Write, PacketWriter.Len() = %d, want 3", pw.Len())
	}
}

func TestPacketWriterReset(t *testing.T) {
	pw := NewPacketWriter()
	pw.Write([]byte{0x01, 0x02, 0x03})
	pw.Reset()

	if pw.Len() != 0 {
		t.Errorf("after Reset, PacketWriter.Len() = %d, want 0", pw.Len())
	}
	if len(pw.Bytes()) != 0 {
		t.Errorf("after Reset, PacketWriter.Bytes() = %x, want empty", pw.Bytes())
	}
}
