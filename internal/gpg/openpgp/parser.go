package openpgp

import (
	"errors"
	"fmt"
	"io"
)

// ParsedPacket represents a parsed OpenPGP packet.
type ParsedPacket struct {
	Tag  byte
	Body []byte
}

// PacketReader reads OpenPGP packets from a byte stream.
type PacketReader struct {
	data []byte
	pos  int
}

// NewPacketReader creates a new packet reader from raw bytes.
func NewPacketReader(data []byte) *PacketReader {
	return &PacketReader{data: data, pos: 0}
}

// Next reads the next packet from the stream.
// Returns io.EOF when there are no more packets.
func (r *PacketReader) Next() (*ParsedPacket, error) {
	if r.pos >= len(r.data) {
		return nil, io.EOF
	}

	// Read packet tag byte
	tagByte := r.data[r.pos]
	r.pos++

	if tagByte&0x80 == 0 {
		return nil, errors.New("invalid packet: bit 7 not set")
	}

	var tag byte
	var bodyLen int
	var err error

	if tagByte&0x40 != 0 {
		// New format packet (bit 6 set)
		tag = tagByte & 0x3F
		bodyLen, err = r.readNewFormatLength()
	} else {
		// Old format packet (bit 6 clear)
		tag = (tagByte & 0x3C) >> 2
		lengthType := tagByte & 0x03
		bodyLen, err = r.readOldFormatLength(lengthType)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to read packet length: %w", err)
	}

	if r.pos+bodyLen > len(r.data) {
		return nil, fmt.Errorf("packet body extends beyond data: need %d bytes, have %d", bodyLen, len(r.data)-r.pos)
	}

	body := r.data[r.pos : r.pos+bodyLen]
	r.pos += bodyLen

	return &ParsedPacket{Tag: tag, Body: body}, nil
}

// readNewFormatLength reads a new-format packet length.
// RFC 4880 section 4.2.2
func (r *PacketReader) readNewFormatLength() (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.ErrUnexpectedEOF
	}

	first := r.data[r.pos]
	r.pos++

	if first < 192 {
		// One-octet length
		return int(first), nil
	} else if first < 224 {
		// Two-octet length
		if r.pos >= len(r.data) {
			return 0, io.ErrUnexpectedEOF
		}
		second := r.data[r.pos]
		r.pos++
		return ((int(first) - 192) << 8) + int(second) + 192, nil
	} else if first == 255 {
		// Five-octet length
		if r.pos+4 > len(r.data) {
			return 0, io.ErrUnexpectedEOF
		}
		length := int(r.data[r.pos])<<24 | int(r.data[r.pos+1])<<16 |
			int(r.data[r.pos+2])<<8 | int(r.data[r.pos+3])
		r.pos += 4
		return length, nil
	} else {
		// Partial body length (224-254)
		// For simplicity, we don't support partial body lengths in parsing
		return 0, errors.New("partial body lengths not supported")
	}
}

// readOldFormatLength reads an old-format packet length.
// RFC 4880 section 4.2.1
func (r *PacketReader) readOldFormatLength(lengthType byte) (int, error) {
	switch lengthType {
	case 0:
		// One-octet length
		if r.pos >= len(r.data) {
			return 0, io.ErrUnexpectedEOF
		}
		length := int(r.data[r.pos])
		r.pos++
		return length, nil
	case 1:
		// Two-octet length
		if r.pos+2 > len(r.data) {
			return 0, io.ErrUnexpectedEOF
		}
		length := int(r.data[r.pos])<<8 | int(r.data[r.pos+1])
		r.pos += 2
		return length, nil
	case 2:
		// Four-octet length
		if r.pos+4 > len(r.data) {
			return 0, io.ErrUnexpectedEOF
		}
		length := int(r.data[r.pos])<<24 | int(r.data[r.pos+1])<<16 |
			int(r.data[r.pos+2])<<8 | int(r.data[r.pos+3])
		r.pos += 4
		return length, nil
	case 3:
		// Indeterminate length - read until end of data
		return len(r.data) - r.pos, nil
	default:
		return 0, fmt.Errorf("invalid length type: %d", lengthType)
	}
}

// Remaining returns true if there are more bytes to read.
func (r *PacketReader) Remaining() int {
	return len(r.data) - r.pos
}

// ParseAllPackets parses all packets from raw data.
func ParseAllPackets(data []byte) ([]*ParsedPacket, error) {
	reader := NewPacketReader(data)
	var packets []*ParsedPacket

	for {
		pkt, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		packets = append(packets, pkt)
	}

	return packets, nil
}
