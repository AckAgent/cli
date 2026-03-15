package age

import (
	"crypto/rand"
	"fmt"
	"io"
	"strings"
)

// secureRandom is the source of randomness for key generation
var secureRandom io.Reader = rand.Reader

// bech32 character set
const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

// bech32Encode encodes data with the given HRP using bech32
func bech32Encode(hrp string, data []byte) (string, error) {
	// Convert 8-bit data to 5-bit groups
	converted := convertBits(data, 8, 5, true)
	if converted == nil {
		return "", fmt.Errorf("failed to convert bits")
	}

	// Compute checksum
	checksum := bech32Checksum(hrp, converted)

	// Build result
	var result strings.Builder
	result.WriteString(strings.ToLower(hrp))
	result.WriteByte('1')
	for _, b := range converted {
		result.WriteByte(charset[b])
	}
	for _, b := range checksum {
		result.WriteByte(charset[b])
	}

	return result.String(), nil
}

// bech32Decode decodes a bech32 string, returning HRP and data
func bech32Decode(s string) (string, []byte, error) {
	// Convert to lowercase
	s = strings.ToLower(s)

	// Find separator
	pos := strings.LastIndex(s, "1")
	if pos < 1 || pos+7 > len(s) {
		return "", nil, fmt.Errorf("invalid bech32 string")
	}

	hrp := s[:pos]
	dataStr := s[pos+1:]

	// Decode characters
	data := make([]byte, len(dataStr))
	for i, c := range dataStr {
		idx := strings.IndexByte(charset, byte(c))
		if idx < 0 {
			return "", nil, fmt.Errorf("invalid character: %c", c)
		}
		data[i] = byte(idx)
	}

	// Verify checksum (last 6 characters)
	if !bech32VerifyChecksum(hrp, data) {
		return "", nil, fmt.Errorf("invalid checksum")
	}

	// Remove checksum and convert back to 8-bit
	data = data[:len(data)-6]
	converted := convertBits(data, 5, 8, false)
	if converted == nil {
		return "", nil, fmt.Errorf("failed to convert bits")
	}

	return hrp, converted, nil
}

// convertBits converts between bit groups
func convertBits(data []byte, fromBits, toBits int, pad bool) []byte {
	acc := 0
	bits := 0
	var result []byte
	maxv := (1 << toBits) - 1

	for _, value := range data {
		acc = (acc << fromBits) | int(value)
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			result = append(result, byte((acc>>bits)&maxv))
		}
	}

	if pad {
		if bits > 0 {
			result = append(result, byte((acc<<(toBits-bits))&maxv))
		}
	} else if bits >= fromBits || ((acc<<(toBits-bits))&maxv) != 0 {
		return nil
	}

	return result
}

// bech32Polymod computes the bech32 checksum polymod
func bech32Polymod(values []byte) int {
	gen := []int{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := 1
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ int(v)
		for i := 0; i < 5; i++ {
			if (top>>i)&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

// hrpExpand expands HRP for checksum computation
func hrpExpand(hrp string) []byte {
	result := make([]byte, len(hrp)*2+1)
	for i, c := range hrp {
		result[i] = byte(c >> 5)
		result[len(hrp)+1+i] = byte(c & 31)
	}
	result[len(hrp)] = 0
	return result
}

// bech32Checksum computes the 6-byte bech32 checksum
func bech32Checksum(hrp string, data []byte) []byte {
	values := append(hrpExpand(hrp), data...)
	values = append(values, []byte{0, 0, 0, 0, 0, 0}...)
	polymod := bech32Polymod(values) ^ 1
	checksum := make([]byte, 6)
	for i := 0; i < 6; i++ {
		checksum[i] = byte((polymod >> (5 * (5 - i))) & 31)
	}
	return checksum
}

// bech32VerifyChecksum verifies the checksum of bech32 data
func bech32VerifyChecksum(hrp string, data []byte) bool {
	return bech32Polymod(append(hrpExpand(hrp), data...)) == 1
}
