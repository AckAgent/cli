package openpgp

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Armor types
const (
	ArmorSignature  = "PGP SIGNATURE"
	ArmorPublicKey  = "PGP PUBLIC KEY BLOCK"
	ArmorPrivateKey = "PGP PRIVATE KEY BLOCK"
	ArmorMessage    = "PGP MESSAGE"
)

// CRC24Init is the initial value for CRC24.
const CRC24Init = 0xB704CE

// CRC24Poly is the polynomial for CRC24.
const CRC24Poly = 0x1864CFB

// CRC24 computes the CRC24 checksum used in OpenPGP ASCII armor.
func CRC24(data []byte) uint32 {
	crc := uint32(CRC24Init)
	for _, b := range data {
		crc ^= uint32(b) << 16
		for i := 0; i < 8; i++ {
			crc <<= 1
			if crc&0x1000000 != 0 {
				crc ^= CRC24Poly
			}
		}
	}
	return crc & 0xFFFFFF
}

// EncodeCRC24 returns the base64-encoded CRC24 checksum prefixed with '='.
func EncodeCRC24(data []byte) string {
	crc := CRC24(data)
	crcBytes := []byte{
		byte(crc >> 16),
		byte(crc >> 8),
		byte(crc),
	}
	return "=" + base64.StdEncoding.EncodeToString(crcBytes)
}

// Armor encodes data in OpenPGP ASCII armor format.
func Armor(armorType string, data []byte) string {
	var sb strings.Builder

	sb.WriteString("-----BEGIN ")
	sb.WriteString(armorType)
	sb.WriteString("-----\n")

	// Encode data as base64 with line wrapping at 64 characters
	encoded := base64.StdEncoding.EncodeToString(data)
	for len(encoded) > 64 {
		sb.WriteString(encoded[:64])
		sb.WriteByte('\n')
		encoded = encoded[64:]
	}
	if len(encoded) > 0 {
		sb.WriteString(encoded)
		sb.WriteByte('\n')
	}

	// Add CRC
	sb.WriteString(EncodeCRC24(data))
	sb.WriteByte('\n')

	sb.WriteString("-----END ")
	sb.WriteString(armorType)
	sb.WriteString("-----\n")

	return sb.String()
}

// ArmorSig creates an ASCII-armored signature.
func ArmorSig(sigPacket []byte) string {
	return Armor(ArmorSignature, sigPacket)
}

// Dearmor decodes ASCII-armored data, returning the binary data and armor type.
// If the input is not armored, it returns the input unchanged with an empty type.
func Dearmor(data []byte) ([]byte, string, error) {
	// Check if data looks like armor
	str := string(data)
	if !strings.Contains(str, "-----BEGIN PGP ") {
		// Not armored, return as-is
		return data, "", nil
	}

	// Find begin marker
	beginIdx := strings.Index(str, "-----BEGIN PGP ")
	if beginIdx == -1 {
		return data, "", nil
	}

	// Extract armor type
	afterBegin := str[beginIdx+15:]
	endOfType := strings.Index(afterBegin, "-----")
	if endOfType == -1 {
		return nil, "", errors.New("malformed armor: missing end of BEGIN marker")
	}
	armorType := "PGP " + afterBegin[:endOfType]

	// Find end marker
	endMarker := "-----END " + armorType + "-----"
	endIdx := strings.Index(str, endMarker)
	if endIdx == -1 {
		return nil, "", errors.New("malformed armor: missing END marker")
	}

	// Extract content between markers
	contentStart := beginIdx + 15 + endOfType + 5 // after "-----"
	content := str[contentStart:endIdx]

	// Skip any headers (lines with colons before blank line)
	lines := strings.Split(content, "\n")
	dataLines := []string{}
	pastHeaders := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !pastHeaders {
			if line == "" {
				pastHeaders = true
			} else if !strings.Contains(line, ":") {
				// First non-header, non-empty line
				pastHeaders = true
				dataLines = append(dataLines, line)
			}
			// Skip header lines
		} else {
			if line != "" && !strings.HasPrefix(line, "=") {
				dataLines = append(dataLines, line)
			} else if strings.HasPrefix(line, "=") {
				// CRC line, stop
				break
			}
		}
	}

	// Decode base64
	encoded := strings.Join(dataLines, "")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decode base64: %w", err)
	}

	return decoded, armorType, nil
}
