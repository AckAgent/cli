package openpgp

import "fmt"

// EncodeMPIFromBytes encodes raw bytes as an OpenPGP MPI.
// Leading zero bytes are stripped before encoding.
func EncodeMPIFromBytes(data []byte) []byte {
	// Strip leading zeros
	start := 0
	for start < len(data) && data[start] == 0 {
		start++
	}

	if start == len(data) {
		return []byte{0, 0}
	}

	data = data[start:]

	// Calculate bit length
	bitLen := (len(data)-1)*8 + bitLength(data[0])

	result := make([]byte, 2+len(data))
	result[0] = byte(bitLen >> 8)
	result[1] = byte(bitLen)
	copy(result[2:], data)

	return result
}

// DecodeMPI decodes an OpenPGP MPI starting at the given offset.
// Returns the raw bytes, number of bytes consumed (including the 2-byte header), and any error.
func DecodeMPI(data []byte, offset int) (value []byte, bytesConsumed int, err error) {
	if offset+2 > len(data) {
		return nil, 0, fmt.Errorf("MPI header extends beyond data at offset %d", offset)
	}

	bitCount := int(data[offset])<<8 | int(data[offset+1])
	byteLen := (bitCount + 7) / 8

	if offset+2+byteLen > len(data) {
		return nil, 0, fmt.Errorf("MPI body extends beyond data: need %d bytes at offset %d", byteLen, offset+2)
	}

	return data[offset+2 : offset+2+byteLen], 2 + byteLen, nil
}

// bitLength returns the number of significant bits in a byte.
func bitLength(b byte) int {
	bits := 0
	for b != 0 {
		bits++
		b >>= 1
	}
	return bits
}
