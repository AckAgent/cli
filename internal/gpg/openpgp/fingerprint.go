package openpgp

import (
	"crypto/elliptic"
	"crypto/sha1"
	"encoding/hex"
	"strings"
	"time"
)

// V4Fingerprint computes the V4 fingerprint for an ECDSA P-256 public key.
// The public key should be 33 bytes compressed (0x02/0x03 || X) or 65 bytes uncompressed (0x04 || X || Y).
// OpenPGP requires uncompressed format for fingerprint computation, so compressed keys
// are decompressed internally.
func V4Fingerprint(publicKey []byte, creationTime time.Time) []byte {
	// Build the public key packet body (decompresses if needed)
	body := buildECDSAPublicKeyBody(publicKey, creationTime)

	// V4 fingerprint = SHA1(0x99 || 2-byte length || body)
	h := sha1.New()
	h.Write([]byte{0x99})
	h.Write([]byte{byte(len(body) >> 8), byte(len(body))})
	h.Write(body)

	return h.Sum(nil)
}

// KeyIDFromFingerprint extracts the 8-byte key ID from a V4 fingerprint.
// The key ID is the low 64 bits of the fingerprint.
func KeyIDFromFingerprint(fingerprint []byte) uint64 {
	if len(fingerprint) < 8 {
		return 0
	}
	// Key ID is last 8 bytes
	fp := fingerprint[len(fingerprint)-8:]
	var id uint64
	for _, b := range fp {
		id = (id << 8) | uint64(b)
	}
	return id
}

// FormatFingerprint formats a fingerprint as a hex string with spaces.
func FormatFingerprint(fp []byte) string {
	hexStr := strings.ToUpper(hex.EncodeToString(fp))
	return formatHexWithSpaces(hexStr)
}

// FormatFingerprintHex formats a hex string fingerprint with spaces.
// Input should be a 40-character hex string like "A1D597197F5C1DACB3E3BB7862BF2FC536D562FF"
func FormatFingerprintHex(hexStr string) string {
	return formatHexWithSpaces(strings.ToUpper(hexStr))
}

// formatHexWithSpaces formats a hex string as groups of 4 characters separated by spaces.
func formatHexWithSpaces(hexStr string) string {
	// Format as groups of 4 characters
	var parts []string
	for i := 0; i < len(hexStr); i += 4 {
		end := i + 4
		if end > len(hexStr) {
			end = len(hexStr)
		}
		parts = append(parts, hexStr[i:end])
	}
	return strings.Join(parts, " ")
}

// ParseFingerprint parses a fingerprint string (with or without spaces) back to bytes.
// Accepts formats like "XXXX XXXX..." or "XXXXXXXXXXXX..."
func ParseFingerprint(s string) []byte {
	// Remove all spaces and convert to lowercase for hex decoding
	cleanHex := strings.ReplaceAll(s, " ", "")
	fp, err := hex.DecodeString(cleanHex)
	if err != nil {
		return nil
	}
	return fp
}

// FormatKeyID formats a key ID as a hex string.
func FormatKeyID(keyID uint64) string {
	return strings.ToUpper(hex.EncodeToString([]byte{
		byte(keyID >> 56),
		byte(keyID >> 48),
		byte(keyID >> 40),
		byte(keyID >> 32),
		byte(keyID >> 24),
		byte(keyID >> 16),
		byte(keyID >> 8),
		byte(keyID),
	}))
}

// buildECDSAPublicKeyBody builds the body of an ECDSA public key packet.
// Accepts compressed (33 bytes) or uncompressed (65 bytes) P-256 keys.
// OpenPGP requires uncompressed format, so compressed keys are decompressed internally.
func buildECDSAPublicKeyBody(publicKey []byte, creationTime time.Time) []byte {
	pw := NewPacketWriter()

	// Version 4
	pw.WriteByte(4)

	// Creation time (4 bytes, big-endian)
	ts := uint32(creationTime.Unix())
	pw.WriteUint32(ts)

	// Algorithm (ECDSA = 19)
	pw.WriteByte(PubKeyAlgoECDSA)

	// OID length + OID
	pw.WriteByte(byte(len(OIDP256)))
	pw.Write(OIDP256)

	// OpenPGP requires uncompressed EC point (0x04 || X || Y)
	uncompressed := decompressP256ForOpenPGP(publicKey)
	pw.Write(EncodeMPIFromBytes(uncompressed))

	return pw.Bytes()
}

// decompressP256ForOpenPGP decompresses a P-256 public key if it is in compressed format.
// Returns the uncompressed form (0x04 || X || Y) for OpenPGP encoding.
func decompressP256ForOpenPGP(publicKey []byte) []byte {
	if len(publicKey) == 33 && (publicKey[0] == 0x02 || publicKey[0] == 0x03) {
		x, y := elliptic.UnmarshalCompressed(elliptic.P256(), publicKey)
		if x != nil {
			return elliptic.Marshal(elliptic.P256(), x, y)
		}
	}
	// Already uncompressed or unknown format, return as-is
	return publicKey
}

// BuildPublicKeyPacket builds a complete public key packet.
func BuildPublicKeyPacket(publicKey []byte, creationTime time.Time) []byte {
	body := buildECDSAPublicKeyBody(publicKey, creationTime)
	return BuildPacket(PacketTagPublicKey, body)
}

// V4FingerprintEd25519 computes the V4 fingerprint for an Ed25519 public key.
// The public key should be 32 bytes.
func V4FingerprintEd25519(publicKey []byte, creationTime time.Time) []byte {
	// Build the public key packet body
	body := buildEdDSAPublicKeyBody(publicKey, creationTime)

	// V4 fingerprint = SHA1(0x99 || 2-byte length || body)
	h := sha1.New()
	h.Write([]byte{0x99})
	h.Write([]byte{byte(len(body) >> 8), byte(len(body))})
	h.Write(body)

	return h.Sum(nil)
}

// buildEdDSAPublicKeyBody builds the body of an EdDSA (Ed25519) public key packet.
func buildEdDSAPublicKeyBody(publicKey []byte, creationTime time.Time) []byte {
	pw := NewPacketWriter()

	// Version 4
	pw.WriteByte(4)

	// Creation time (4 bytes, big-endian)
	ts := uint32(creationTime.Unix())
	pw.WriteUint32(ts)

	// Algorithm (EdDSA = 22)
	pw.WriteByte(PubKeyAlgoEdDSA)

	// OID length + OID
	pw.WriteByte(byte(len(OIDEd25519)))
	pw.Write(OIDEd25519)

	// Public key point (MPI-encoded, with 0x40 prefix for compressed EdDSA point)
	// Format: 0x40 || public key (32 bytes)
	point := make([]byte, 1+len(publicKey))
	point[0] = 0x40 // EdDSA compressed point indicator
	copy(point[1:], publicKey)
	pw.Write(EncodeMPIFromBytes(point))

	return pw.Bytes()
}

// BuildPublicKeyPacketEd25519 builds a complete Ed25519 public key packet.
func BuildPublicKeyPacketEd25519(publicKey []byte, creationTime time.Time) []byte {
	body := buildEdDSAPublicKeyBody(publicKey, creationTime)
	return BuildPacket(PacketTagPublicKey, body)
}

// BuildUserIDPacket builds a user ID packet.
func BuildUserIDPacket(userID string) []byte {
	return BuildPacket(PacketTagUserID, []byte(userID))
}
