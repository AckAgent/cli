package openpgp

import (
	"errors"
	"fmt"
)

// SEIPDPacket represents a Symmetrically Encrypted Integrity Protected Data packet (tag 18).
// RFC 4880 section 5.13 (v1), RFC 9580 (v2)
type SEIPDPacket struct {
	Version       byte   // 1 for RFC 4880, 2 for RFC 9580 (AEAD)
	CipherAlgo    byte   // Symmetric cipher algorithm (v2 only)
	AEADAlgo      byte   // AEAD algorithm (v2 only)
	ChunkSizeByte byte   // Chunk size exponent (v2 only)
	Salt          []byte // 32-byte salt (v2 only)
	Ciphertext    []byte // Encrypted data
}

// ChunkSize returns the chunk size in bytes for v2 SEIPD.
// Chunk size = 2^(chunkSizeByte + 6)
func (s *SEIPDPacket) ChunkSize() int {
	if s.Version != SEIPDVersion2 {
		return 0
	}
	return 1 << (int(s.ChunkSizeByte) + 6)
}

// ParseSEIPD parses a SEIPD packet body.
func ParseSEIPD(body []byte) (*SEIPDPacket, error) {
	if len(body) < 1 {
		return nil, errors.New("SEIPD packet too short")
	}

	version := body[0]
	switch version {
	case SEIPDVersion1:
		return parseSEIPDv1(body)
	case SEIPDVersion2:
		return parseSEIPDv2(body)
	default:
		return nil, fmt.Errorf("unsupported SEIPD version: %d", version)
	}
}

// parseSEIPDv1 parses a version 1 SEIPD packet (RFC 4880).
// Version 1: version (1 byte) || encrypted_data
// The encrypted data uses CFB mode with MDC.
func parseSEIPDv1(body []byte) (*SEIPDPacket, error) {
	if len(body) < 2 {
		return nil, errors.New("SEIPD v1 packet too short")
	}

	return &SEIPDPacket{
		Version:    SEIPDVersion1,
		Ciphertext: body[1:],
	}, nil
}

// parseSEIPDv2 parses a version 2 SEIPD packet (RFC 9580 / crypto-refresh).
// Version 2: version (1) || cipher_algo (1) || aead_algo (1) || chunk_size (1) || salt (32) || encrypted_data
func parseSEIPDv2(body []byte) (*SEIPDPacket, error) {
	// Minimum: version(1) + cipher(1) + aead(1) + chunk(1) + salt(32) = 36 bytes
	if len(body) < 36 {
		return nil, fmt.Errorf("SEIPD v2 packet too short: %d bytes", len(body))
	}

	cipherAlgo := body[1]
	aeadAlgo := body[2]
	chunkSize := body[3]
	salt := make([]byte, 32)
	copy(salt, body[4:36])
	ciphertext := body[36:]

	return &SEIPDPacket{
		Version:       SEIPDVersion2,
		CipherAlgo:    cipherAlgo,
		AEADAlgo:      aeadAlgo,
		ChunkSizeByte: chunkSize,
		Salt:          salt,
		Ciphertext:    ciphertext,
	}, nil
}

// BuildSEIPDv1 creates a version 1 SEIPD packet body.
func BuildSEIPDv1(ciphertext []byte) []byte {
	body := make([]byte, 1+len(ciphertext))
	body[0] = SEIPDVersion1
	copy(body[1:], ciphertext)
	return body
}

// BuildSEIPDv2 creates a version 2 SEIPD packet body.
func BuildSEIPDv2(cipherAlgo, aeadAlgo, chunkSize byte, salt, ciphertext []byte) ([]byte, error) {
	if len(salt) != 32 {
		return nil, fmt.Errorf("salt must be 32 bytes, got %d", len(salt))
	}

	body := make([]byte, 36+len(ciphertext))
	body[0] = SEIPDVersion2
	body[1] = cipherAlgo
	body[2] = aeadAlgo
	body[3] = chunkSize
	copy(body[4:36], salt)
	copy(body[36:], ciphertext)
	return body, nil
}

// EncryptedMessage represents a parsed encrypted OpenPGP message.
type EncryptedMessage struct {
	PKESKPackets []*PKESKPacket
	SEIPDPacket  *SEIPDPacket
}

// ParseEncryptedMessage parses an encrypted OpenPGP message.
// An encrypted message consists of one or more PKESK packets followed by a SEIPD packet.
func ParseEncryptedMessage(data []byte) (*EncryptedMessage, error) {
	packets, err := ParseAllPackets(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse packets: %w", err)
	}

	if len(packets) == 0 {
		return nil, errors.New("no packets found")
	}

	msg := &EncryptedMessage{}

	for i, pkt := range packets {
		switch pkt.Tag {
		case PacketTagPKESK:
			pkesk, err := ParsePKESK(pkt.Body)
			if err != nil {
				return nil, fmt.Errorf("failed to parse PKESK packet %d: %w", i, err)
			}
			msg.PKESKPackets = append(msg.PKESKPackets, pkesk)

		case PacketTagSEIPD:
			if msg.SEIPDPacket != nil {
				return nil, errors.New("multiple SEIPD packets not supported")
			}
			seipd, err := ParseSEIPD(pkt.Body)
			if err != nil {
				return nil, fmt.Errorf("failed to parse SEIPD packet: %w", err)
			}
			msg.SEIPDPacket = seipd

		default:
			// Skip unknown packets
		}
	}

	if len(msg.PKESKPackets) == 0 {
		return nil, errors.New("no PKESK packets found")
	}
	if msg.SEIPDPacket == nil {
		return nil, errors.New("no SEIPD packet found")
	}

	return msg, nil
}

// FindMatchingPKESK finds the PKESK packet that matches one of the given fingerprints.
// Returns the matching PKESK and the fingerprint it matched.
func (m *EncryptedMessage) FindMatchingPKESK(fingerprints [][]byte) (*PKESKPacket, []byte) {
	for _, pkesk := range m.PKESKPackets {
		// Check for wildcard key ID first (matches any key)
		if pkesk.IsWildcardKeyID() {
			if len(fingerprints) > 0 {
				return pkesk, fingerprints[0]
			}
			continue
		}

		// Check for specific key ID match
		for _, fp := range fingerprints {
			if pkesk.MatchesKeyID(fp) {
				return pkesk, fp
			}
		}
	}
	return nil, nil
}
