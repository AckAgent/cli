package openpgp

import (
	"bytes"
	"errors"
	"fmt"
)

// PKESKPacket represents a Public Key Encrypted Session Key packet (tag 1).
// RFC 4880 section 5.1
type PKESKPacket struct {
	Version        byte   // Packet version (must be 3)
	KeyID          []byte // 8-byte key ID of recipient
	Algorithm      byte   // Public key algorithm
	EphemeralPoint []byte // For ECDH: 65-byte uncompressed point (04 || X || Y)
	WrappedKey     []byte // AES-wrapped session key
}

// ParsePKESK parses a PKESK packet body.
func ParsePKESK(body []byte) (*PKESKPacket, error) {
	if len(body) < 10 {
		return nil, errors.New("PKESK packet too short")
	}

	version := body[0]
	if version != PKESKVersion3 {
		return nil, fmt.Errorf("unsupported PKESK version: %d (only version 3 supported)", version)
	}

	keyID := make([]byte, 8)
	copy(keyID, body[1:9])

	algorithm := body[9]

	switch algorithm {
	case PubKeyAlgoECDH:
		return parseECDHPKESK(version, keyID, algorithm, body[10:])
	default:
		return nil, fmt.Errorf("unsupported public key algorithm: %d", algorithm)
	}
}

// parseECDHPKESK parses the ECDH-specific portion of a PKESK packet.
// RFC 6637 section 8
func parseECDHPKESK(version byte, keyID []byte, algorithm byte, data []byte) (*PKESKPacket, error) {
	if len(data) < 2 {
		return nil, errors.New("ECDH PKESK data too short")
	}

	// Read MPI for ephemeral point
	mpiLen, ephemeral, err := readMPI(data)
	if err != nil {
		return nil, fmt.Errorf("failed to read ephemeral point MPI: %w", err)
	}

	// Ephemeral point is 65 bytes (04 || X || Y) for P-256 uncompressed,
	// or 33 bytes (40 || reversed-key) for Curve25519
	if len(ephemeral) == 65 {
		if ephemeral[0] != 0x04 {
			return nil, fmt.Errorf("expected uncompressed P-256 point (0x04 prefix), got 0x%02x", ephemeral[0])
		}
	} else if len(ephemeral) == 33 {
		if ephemeral[0] != 0x40 {
			return nil, fmt.Errorf("expected Curve25519 point (0x40 prefix), got 0x%02x", ephemeral[0])
		}
	} else {
		return nil, fmt.Errorf("unexpected ephemeral point length: %d (expected 65 for P-256 or 33 for Curve25519)", len(ephemeral))
	}

	remaining := data[mpiLen:]
	if len(remaining) < 1 {
		return nil, errors.New("missing wrapped key length")
	}

	// Read wrapped key (length-prefixed)
	wrappedKeyLen := int(remaining[0])
	if len(remaining) < 1+wrappedKeyLen {
		return nil, fmt.Errorf("wrapped key extends beyond packet: need %d, have %d", wrappedKeyLen, len(remaining)-1)
	}
	wrappedKey := remaining[1 : 1+wrappedKeyLen]

	return &PKESKPacket{
		Version:        version,
		KeyID:          keyID,
		Algorithm:      algorithm,
		EphemeralPoint: ephemeral,
		WrappedKey:     wrappedKey,
	}, nil
}

// readMPI reads a multi-precision integer from data.
// Returns the number of bytes consumed and the MPI value.
func readMPI(data []byte) (int, []byte, error) {
	if len(data) < 2 {
		return 0, nil, errors.New("MPI too short")
	}

	// MPI format: 2-byte big-endian bit count, followed by the integer bytes
	bitLen := int(data[0])<<8 | int(data[1])
	byteLen := (bitLen + 7) / 8

	if len(data) < 2+byteLen {
		return 0, nil, fmt.Errorf("MPI data too short: need %d bytes, have %d", byteLen, len(data)-2)
	}

	return 2 + byteLen, data[2 : 2+byteLen], nil
}

// KeyIDString returns the key ID as a hex string.
func (p *PKESKPacket) KeyIDString() string {
	return fmt.Sprintf("%X", p.KeyID)
}

// MatchesKeyID checks if this PKESK is for a key with the given fingerprint.
// The key ID is the last 8 bytes of the V4 fingerprint.
func (p *PKESKPacket) MatchesKeyID(fingerprint []byte) bool {
	if len(fingerprint) < 8 {
		return false
	}
	// Key ID is last 8 bytes of fingerprint for V4 keys
	keyID := fingerprint[len(fingerprint)-8:]
	return bytes.Equal(p.KeyID, keyID)
}

// IsWildcardKeyID returns true if the key ID is all zeros (anonymous recipient).
func (p *PKESKPacket) IsWildcardKeyID() bool {
	for _, b := range p.KeyID {
		if b != 0 {
			return false
		}
	}
	return true
}

// BuildPKESK creates a PKESK packet body for ECDH.
// ephemeralPoint must be 65 bytes (04 || X || Y) for P-256,
// or 33 bytes (40 || reversed-key) for Curve25519.
// wrappedKey is the AES-wrapped session key.
func BuildPKESK(keyID []byte, ephemeralPoint, wrappedKey []byte) ([]byte, error) {
	if len(keyID) != 8 {
		return nil, fmt.Errorf("key ID must be 8 bytes, got %d", len(keyID))
	}
	if len(ephemeralPoint) != 65 && len(ephemeralPoint) != 33 {
		return nil, fmt.Errorf("ephemeral point must be 65 bytes (P-256) or 33 bytes (Curve25519), got %d", len(ephemeralPoint))
	}

	pw := NewPacketWriter()

	// Version
	pw.WriteByte(PKESKVersion3)

	// Key ID (8 bytes)
	pw.Write(keyID)

	// Algorithm (ECDH = 18)
	pw.WriteByte(PubKeyAlgoECDH)

	// Ephemeral point as MPI
	pw.Write(EncodeMPIFromBytes(ephemeralPoint))

	// Wrapped key with length prefix
	pw.WriteByte(byte(len(wrappedKey)))
	pw.Write(wrappedKey)

	return pw.Bytes(), nil
}
