package openpgp

import (
	"bytes"
	"testing"
)

func TestNewPacketReader_EmptyData(t *testing.T) {
	reader := NewPacketReader(nil)
	_, err := reader.Next()
	if err == nil {
		t.Error("expected error for empty data")
	}
}

func TestNewPacketReader_Remaining(t *testing.T) {
	// Build two packets
	p1 := BuildPacket(PacketTagSignature, []byte{0x01, 0x02})
	p2 := BuildPacket(PacketTagUserID, []byte{0x03, 0x04, 0x05})
	combined := append(p1, p2...)

	reader := NewPacketReader(combined)

	// Before reading
	remaining := reader.Remaining()
	if remaining != len(combined) {
		t.Errorf("initial Remaining() = %d, want %d", remaining, len(combined))
	}

	// Read first packet
	_, err := reader.Next()
	if err != nil {
		t.Fatalf("Next() error: %v", err)
	}

	remaining2 := reader.Remaining()
	if remaining2 >= remaining {
		t.Errorf("after Next(), Remaining() should decrease: got %d (was %d)", remaining2, remaining)
	}

	// Read second packet
	pkt2, err := reader.Next()
	if err != nil {
		t.Fatalf("Next() second packet error: %v", err)
	}
	if pkt2.Tag != PacketTagUserID {
		t.Errorf("second packet tag = %d, want %d", pkt2.Tag, PacketTagUserID)
	}
}

func TestParseAllPackets_MultiplePackets(t *testing.T) {
	p1 := BuildPacket(PacketTagPublicKey, []byte{0x04, 0x00, 0x00, 0x00, 0x00, 19})
	p2 := BuildPacket(PacketTagUserID, []byte("test@example.com"))
	p3 := BuildPacket(PacketTagSignature, []byte{0x04, 0x00, 0x13, 0x08})
	data := bytes.Join([][]byte{p1, p2, p3}, nil)

	packets, err := ParseAllPackets(data)
	if err != nil {
		t.Fatalf("ParseAllPackets error: %v", err)
	}

	if len(packets) != 3 {
		t.Fatalf("expected 3 packets, got %d", len(packets))
	}

	if packets[0].Tag != PacketTagPublicKey {
		t.Errorf("packet[0].Tag = %d, want %d", packets[0].Tag, PacketTagPublicKey)
	}
	if packets[1].Tag != PacketTagUserID {
		t.Errorf("packet[1].Tag = %d, want %d", packets[1].Tag, PacketTagUserID)
	}
	if packets[2].Tag != PacketTagSignature {
		t.Errorf("packet[2].Tag = %d, want %d", packets[2].Tag, PacketTagSignature)
	}
}

func TestEncodeNewPacketHeader(t *testing.T) {
	tests := []struct {
		name   string
		tag    byte
		length int
	}{
		{"short body", 2, 10},
		{"medium body", 6, 200},
		{"large body", 11, 70000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := EncodeNewPacketHeader(tt.tag, tt.length)
			if len(header) == 0 {
				t.Fatal("header should not be empty")
			}

			// First byte should have bit 7 set (new format indicator)
			// and bit 6 set (new format)
			if header[0]&0xC0 != 0xC0 {
				t.Errorf("first byte 0x%02x missing new format bits", header[0])
			}

			// Tag should be in bits 0-5
			gotTag := header[0] & 0x3F
			if gotTag != tt.tag {
				t.Errorf("tag in header = %d, want %d", gotTag, tt.tag)
			}
		})
	}
}

func TestReadNewFormatLength(t *testing.T) {
	// Test by building a new-format packet and parsing it
	body := bytes.Repeat([]byte{0xAA}, 200)
	header := EncodeNewPacketHeader(PacketTagSignature, len(body))
	fullPacket := append(header, body...)

	reader := NewPacketReader(fullPacket)
	pkt, err := reader.Next()
	if err != nil {
		t.Fatalf("failed to parse new-format packet: %v", err)
	}

	if pkt.Tag != PacketTagSignature {
		t.Errorf("tag = %d, want %d", pkt.Tag, PacketTagSignature)
	}
	if len(pkt.Body) != 200 {
		t.Errorf("body length = %d, want 200", len(pkt.Body))
	}
}

func TestReadNewFormatLength_FiveOctet(t *testing.T) {
	// Build a packet with body > 8383 bytes to trigger 5-octet length encoding
	body := bytes.Repeat([]byte{0xBB}, 10000)
	header := EncodeNewPacketHeader(PacketTagLiteralData, len(body))
	fullPacket := append(header, body...)

	reader := NewPacketReader(fullPacket)
	pkt, err := reader.Next()
	if err != nil {
		t.Fatalf("failed to parse large new-format packet: %v", err)
	}

	if len(pkt.Body) != 10000 {
		t.Errorf("body length = %d, want 10000", len(pkt.Body))
	}
}

func TestOldFormatPacket_OneOctetLength(t *testing.T) {
	// Old format: tag 2 (signature), length type 0 (1-byte length)
	body := []byte{0x01, 0x02, 0x03}
	header := EncodeOldPacketHeader(PacketTagSignature, len(body))
	fullPacket := append(header, body...)

	reader := NewPacketReader(fullPacket)
	pkt, err := reader.Next()
	if err != nil {
		t.Fatalf("old format one-octet: %v", err)
	}
	if pkt.Tag != PacketTagSignature {
		t.Errorf("tag = %d, want %d", pkt.Tag, PacketTagSignature)
	}
	if !bytes.Equal(pkt.Body, body) {
		t.Errorf("body = %x, want %x", pkt.Body, body)
	}
}

func TestOldFormatPacket_TwoOctetLength(t *testing.T) {
	// Old format with 2-byte length (256..65535)
	body := bytes.Repeat([]byte{0xCC}, 300)
	header := EncodeOldPacketHeader(PacketTagSignature, len(body))
	fullPacket := append(header, body...)

	reader := NewPacketReader(fullPacket)
	pkt, err := reader.Next()
	if err != nil {
		t.Fatalf("old format two-octet: %v", err)
	}
	if len(pkt.Body) != 300 {
		t.Errorf("body length = %d, want 300", len(pkt.Body))
	}
}

func TestOldFormatPacket_FourOctetLength(t *testing.T) {
	// Old format with 4-byte length (>= 65536)
	body := bytes.Repeat([]byte{0xDD}, 70000)
	header := EncodeOldPacketHeader(PacketTagSignature, len(body))
	fullPacket := append(header, body...)

	reader := NewPacketReader(fullPacket)
	pkt, err := reader.Next()
	if err != nil {
		t.Fatalf("old format four-octet: %v", err)
	}
	if len(pkt.Body) != 70000 {
		t.Errorf("body length = %d, want 70000", len(pkt.Body))
	}
}

func TestOldFormatPacket_IndeterminateLength(t *testing.T) {
	// Manually build a packet with length type 3 (indeterminate)
	// tag byte: 0x80 | (tag << 2) | 3
	tag := byte(PacketTagSignature)
	tagByte := byte(0x80 | (tag << 2) | 3)
	body := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	fullPacket := append([]byte{tagByte}, body...)

	reader := NewPacketReader(fullPacket)
	pkt, err := reader.Next()
	if err != nil {
		t.Fatalf("old format indeterminate: %v", err)
	}
	if !bytes.Equal(pkt.Body, body) {
		t.Errorf("body = %x, want %x", pkt.Body, body)
	}
}

func TestPacketReader_InvalidBit7(t *testing.T) {
	// First byte with bit 7 clear = invalid
	reader := NewPacketReader([]byte{0x00, 0x01})
	_, err := reader.Next()
	if err == nil {
		t.Error("expected error for invalid packet (bit 7 not set)")
	}
}

func TestPacketReader_BodyExtendsBeyondData(t *testing.T) {
	// Old format claiming 100 bytes but only 2 available
	tagByte := byte(0x80 | (PacketTagSignature << 2) | 0) // 1-byte length
	reader := NewPacketReader([]byte{tagByte, 100, 0x01, 0x02})
	_, err := reader.Next()
	if err == nil {
		t.Error("expected error for body extending beyond data")
	}
}

func TestEncodeOldPacketHeader_AllLengthTypes(t *testing.T) {
	tests := []struct {
		name    string
		bodyLen int
		wantLen int // expected header length
	}{
		{"one octet", 10, 2},     // tag + 1-byte length
		{"two octet", 300, 3},    // tag + 2-byte length
		{"four octet", 70000, 5}, // tag + 4-byte length
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := EncodeOldPacketHeader(PacketTagSignature, tt.bodyLen)
			if len(header) != tt.wantLen {
				t.Errorf("header length = %d, want %d", len(header), tt.wantLen)
			}
			// Verify bit 7 set, bit 6 clear (old format)
			if header[0]&0x80 == 0 {
				t.Error("bit 7 should be set")
			}
			if header[0]&0x40 != 0 {
				t.Error("bit 6 should be clear for old format")
			}
		})
	}
}

func TestBuildPacket_UsesNewFormatForHighTags(t *testing.T) {
	// Tag 18 (SEIPD) must use new format
	body := []byte{0x01}
	pkt := BuildPacket(PacketTagSEIPD, body)
	if pkt[0]&0xC0 != 0xC0 {
		t.Error("tag 18 should use new packet format")
	}

	// Tag 2 (Signature) uses old format
	pkt2 := BuildPacket(PacketTagSignature, body)
	if pkt2[0]&0x40 != 0 {
		t.Error("tag 2 should use old packet format")
	}
}

func TestPacketWriter_WriteUint16(t *testing.T) {
	pw := NewPacketWriter()
	pw.WriteUint16(0xABCD)
	got := pw.Bytes()
	if !bytes.Equal(got, []byte{0xAB, 0xCD}) {
		t.Errorf("WriteUint16(0xABCD) = %x, want abcd", got)
	}
}

func TestPacketWriter_WriteUint32(t *testing.T) {
	pw := NewPacketWriter()
	pw.WriteUint32(0x12345678)
	got := pw.Bytes()
	if !bytes.Equal(got, []byte{0x12, 0x34, 0x56, 0x78}) {
		t.Errorf("WriteUint32(0x12345678) = %x, want 12345678", got)
	}
}
