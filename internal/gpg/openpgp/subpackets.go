package openpgp

import (
	"time"
)

// SubpacketBuilder helps build signature subpacket areas.
type SubpacketBuilder struct {
	pw PacketWriter
}

// NewSubpacketBuilder creates a new subpacket builder.
func NewSubpacketBuilder() *SubpacketBuilder {
	return &SubpacketBuilder{}
}

// AddCreationTime adds a signature creation time subpacket.
func (sb *SubpacketBuilder) AddCreationTime(t time.Time) {
	data := make([]byte, 4)
	ts := uint32(t.Unix())
	data[0] = byte(ts >> 24)
	data[1] = byte(ts >> 16)
	data[2] = byte(ts >> 8)
	data[3] = byte(ts)
	sb.addSubpacket(SubpacketSignatureCreationTime, data, false)
}

// AddIssuer adds an issuer key ID subpacket.
func (sb *SubpacketBuilder) AddIssuer(keyID uint64) {
	data := make([]byte, 8)
	data[0] = byte(keyID >> 56)
	data[1] = byte(keyID >> 48)
	data[2] = byte(keyID >> 40)
	data[3] = byte(keyID >> 32)
	data[4] = byte(keyID >> 24)
	data[5] = byte(keyID >> 16)
	data[6] = byte(keyID >> 8)
	data[7] = byte(keyID)
	sb.addSubpacket(SubpacketIssuer, data, false)
}

// AddIssuerFingerprint adds an issuer fingerprint subpacket (V4 key).
func (sb *SubpacketBuilder) AddIssuerFingerprint(fingerprint []byte) {
	// V4 fingerprint subpacket: version byte + 20-byte fingerprint
	data := make([]byte, 1+len(fingerprint))
	data[0] = 4 // V4 key
	copy(data[1:], fingerprint)
	sb.addSubpacket(SubpacketIssuerFingerprint, data, false)
}

// AddKeyFlags adds a key flags subpacket.
// RFC 4880 section 5.2.3.21
// Common flags:
//   - 0x01: may certify other keys
//   - 0x02: may sign data
//   - 0x04: may encrypt communications
//   - 0x08: may encrypt storage
//   - 0x10: private component may have been split
//   - 0x20: may be used for authentication
func (sb *SubpacketBuilder) AddKeyFlags(flags byte) {
	sb.addSubpacket(SubpacketKeyFlags, []byte{flags}, false)
}

// addSubpacket adds a subpacket with the given type and data.
// If critical is true, the critical bit is set.
func (sb *SubpacketBuilder) addSubpacket(subpacketType byte, data []byte, critical bool) {
	// Subpacket length includes the type byte
	length := 1 + len(data)

	// Encode length
	if length < 192 {
		sb.pw.WriteByte(byte(length))
	} else if length < 16320 {
		length -= 192
		sb.pw.WriteByte(byte((length >> 8) + 192))
		sb.pw.WriteByte(byte(length))
	} else {
		sb.pw.WriteByte(0xFF)
		sb.pw.WriteUint32(uint32(length))
	}

	// Type byte (with critical bit if set)
	typeByte := subpacketType
	if critical {
		typeByte |= 0x80
	}
	sb.pw.WriteByte(typeByte)

	// Data
	sb.pw.Write(data)
}

// Bytes returns the encoded subpackets.
func (sb *SubpacketBuilder) Bytes() []byte {
	return sb.pw.Bytes()
}

// Len returns the total length of encoded subpackets.
func (sb *SubpacketBuilder) Len() int {
	return sb.pw.Len()
}
