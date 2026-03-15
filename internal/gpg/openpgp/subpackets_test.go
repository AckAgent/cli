package openpgp

import (
	"testing"
	"time"
)

func TestNewSubpacketBuilder(t *testing.T) {
	sb := NewSubpacketBuilder()
	if sb.Len() != 0 {
		t.Errorf("new SubpacketBuilder.Len() = %d, want 0", sb.Len())
	}
	if len(sb.Bytes()) != 0 {
		t.Errorf("new SubpacketBuilder.Bytes() should be empty")
	}
}

func TestSubpacketBuilder_AddCreationTime(t *testing.T) {
	sb := NewSubpacketBuilder()
	ts := time.Unix(1700000000, 0)
	sb.AddCreationTime(ts)

	data := sb.Bytes()
	if len(data) == 0 {
		t.Fatal("AddCreationTime produced empty output")
	}
	// Subpacket format: length(1) + type(1) + data(4) = 6 bytes total
	// length = 1 + 4 = 5
	if data[0] != 5 {
		t.Errorf("subpacket length = %d, want 5", data[0])
	}
	if data[1] != SubpacketSignatureCreationTime {
		t.Errorf("subpacket type = %d, want %d", data[1], SubpacketSignatureCreationTime)
	}
}

func TestSubpacketBuilder_AddIssuer(t *testing.T) {
	sb := NewSubpacketBuilder()
	sb.AddIssuer(0x0102030405060708)

	data := sb.Bytes()
	if len(data) == 0 {
		t.Fatal("AddIssuer produced empty output")
	}
	// length = 1 + 8 = 9
	if data[0] != 9 {
		t.Errorf("subpacket length = %d, want 9", data[0])
	}
	if data[1] != SubpacketIssuer {
		t.Errorf("subpacket type = %d, want %d", data[1], SubpacketIssuer)
	}
	// Verify key ID bytes
	expected := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	for i, b := range expected {
		if data[2+i] != b {
			t.Errorf("key ID byte %d = 0x%02x, want 0x%02x", i, data[2+i], b)
		}
	}
}

func TestSubpacketBuilder_AddIssuerFingerprint(t *testing.T) {
	sb := NewSubpacketBuilder()
	fp := make([]byte, 20)
	for i := range fp {
		fp[i] = byte(i + 1)
	}
	sb.AddIssuerFingerprint(fp)

	data := sb.Bytes()
	// length = 1 + 1 (version) + 20 (fingerprint) = 22
	if data[0] != 22 {
		t.Errorf("subpacket length = %d, want 22", data[0])
	}
	if data[1] != SubpacketIssuerFingerprint {
		t.Errorf("subpacket type = %d, want %d", data[1], SubpacketIssuerFingerprint)
	}
	// Version byte
	if data[2] != 4 {
		t.Errorf("version byte = %d, want 4", data[2])
	}
}

func TestSubpacketBuilder_AddKeyFlags(t *testing.T) {
	sb := NewSubpacketBuilder()
	sb.AddKeyFlags(0x0C) // encrypt communications + encrypt storage

	data := sb.Bytes()
	// length = 1 + 1 = 2
	if data[0] != 2 {
		t.Errorf("subpacket length = %d, want 2", data[0])
	}
	if data[1] != SubpacketKeyFlags {
		t.Errorf("subpacket type = %d, want %d", data[1], SubpacketKeyFlags)
	}
	if data[2] != 0x0C {
		t.Errorf("flags = 0x%02x, want 0x0C", data[2])
	}
}

func TestSubpacketBuilder_MultipleSubpackets(t *testing.T) {
	sb := NewSubpacketBuilder()
	sb.AddCreationTime(time.Unix(1700000000, 0))
	sb.AddKeyFlags(0x02) // sign data

	data := sb.Bytes()
	// Should have two subpackets concatenated
	// First: 1 + 1 + 4 = 6 bytes
	// Second: 1 + 1 + 1 = 3 bytes
	expectedLen := 6 + 3
	if len(data) != expectedLen {
		t.Errorf("total length = %d, want %d", len(data), expectedLen)
	}
}

func TestSubpacketBuilder_LargeSubpacket(t *testing.T) {
	sb := NewSubpacketBuilder()
	// Create a large data payload that triggers 2-octet length (192..16319)
	largeData := make([]byte, 200)
	// Use addSubpacket directly via AddIssuerFingerprint with a large fingerprint
	// Instead, test via the builder's internal state
	sb.AddIssuerFingerprint(largeData)

	data := sb.Bytes()
	if len(data) == 0 {
		t.Fatal("large subpacket produced empty output")
	}
	// Length = 1 + 200 = 201, which is >= 192, so uses 2-octet encoding
	// First byte should be >= 192
	if data[0] < 192 {
		t.Errorf("expected 2-octet length encoding, first byte = %d", data[0])
	}
}
