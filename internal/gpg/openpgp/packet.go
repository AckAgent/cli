package openpgp

import (
	"bytes"
)

// PacketWriter helps build OpenPGP packets.
type PacketWriter struct {
	buf bytes.Buffer
}

// NewPacketWriter creates a new packet writer.
func NewPacketWriter() *PacketWriter {
	return &PacketWriter{}
}

// Write implements io.Writer.
func (pw *PacketWriter) Write(p []byte) (n int, err error) {
	return pw.buf.Write(p)
}

// WriteByte writes a single byte.
func (pw *PacketWriter) WriteByte(b byte) error {
	return pw.buf.WriteByte(b)
}

// WriteUint16 writes a 16-bit big-endian value.
func (pw *PacketWriter) WriteUint16(v uint16) {
	pw.buf.WriteByte(byte(v >> 8))
	pw.buf.WriteByte(byte(v))
}

// WriteUint32 writes a 32-bit big-endian value.
func (pw *PacketWriter) WriteUint32(v uint32) {
	pw.buf.WriteByte(byte(v >> 24))
	pw.buf.WriteByte(byte(v >> 16))
	pw.buf.WriteByte(byte(v >> 8))
	pw.buf.WriteByte(byte(v))
}

// Bytes returns the accumulated bytes.
func (pw *PacketWriter) Bytes() []byte {
	return pw.buf.Bytes()
}

// Len returns the number of bytes written.
func (pw *PacketWriter) Len() int {
	return pw.buf.Len()
}

// Reset clears the buffer.
func (pw *PacketWriter) Reset() {
	pw.buf.Reset()
}

// EncodeOldPacketHeader encodes an old-format packet header.
// Old format: 1 byte tag (0x80 | (tag << 2) | length_type), followed by body length.
// Note: Old format only supports tags 0-15.
func EncodeOldPacketHeader(tag byte, bodyLen int) []byte {
	if bodyLen < 256 {
		return []byte{
			0x80 | (tag << 2) | 0,
			byte(bodyLen),
		}
	} else if bodyLen < 65536 {
		return []byte{
			0x80 | (tag << 2) | 1,
			byte(bodyLen >> 8),
			byte(bodyLen),
		}
	} else {
		return []byte{
			0x80 | (tag << 2) | 2,
			byte(bodyLen >> 24),
			byte(bodyLen >> 16),
			byte(bodyLen >> 8),
			byte(bodyLen),
		}
	}
}

// EncodeNewPacketHeader encodes a new-format packet header.
// New format: 1 byte (0xC0 | tag), followed by length encoding.
// Required for tags > 15 (like SEIPD which is tag 18).
// RFC 4880 Section 4.2.2
func EncodeNewPacketHeader(tag byte, bodyLen int) []byte {
	header := []byte{0xC0 | tag}

	// New format length encoding (RFC 4880 Section 4.2.2.1-4.2.2.3)
	if bodyLen < 192 {
		// One-octet length
		header = append(header, byte(bodyLen))
	} else if bodyLen < 8384 {
		// Two-octet length: (((first_octet - 192) << 8) + second_octet) + 192
		adjusted := bodyLen - 192
		header = append(header, byte((adjusted>>8)+192))
		header = append(header, byte(adjusted))
	} else {
		// Five-octet length: 0xFF + 4-byte big-endian
		header = append(header, 0xFF)
		header = append(header, byte(bodyLen>>24))
		header = append(header, byte(bodyLen>>16))
		header = append(header, byte(bodyLen>>8))
		header = append(header, byte(bodyLen))
	}

	return header
}

// BuildPacket creates a complete packet with header and body.
// Uses new format for tags > 15, old format for tags 0-15.
func BuildPacket(tag byte, body []byte) []byte {
	var header []byte
	if tag > 15 {
		// Must use new packet format for tags > 15
		header = EncodeNewPacketHeader(tag, len(body))
	} else {
		header = EncodeOldPacketHeader(tag, len(body))
	}
	result := make([]byte, len(header)+len(body))
	copy(result, header)
	copy(result[len(header):], body)
	return result
}
