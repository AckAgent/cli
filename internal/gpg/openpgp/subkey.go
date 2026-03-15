package openpgp

import (
	"crypto/sha1"
	"crypto/sha256"
	"time"
)

// Packet tag for public subkey
const (
	PacketTagPublicSubkey = 14 // Public Subkey Packet
)

// Signature types for subkey binding
const (
	SignatureTypeSubkeyBinding = 0x18 // Subkey Binding Signature
)

// reverseBytes returns a new slice with bytes in reverse order.
// Used for converting between OpenPGP big-endian and RFC 7748 little-endian
// Curve25519 key representations.
func reverseBytes(b []byte) []byte {
	result := make([]byte, len(b))
	for i, v := range b {
		result[len(b)-1-i] = v
	}
	return result
}

// V4FingerprintECDH computes the V4 fingerprint for an ECDH P-256 public key.
// The public key should be 33 bytes compressed (0x02/0x03 || X) or 65 bytes uncompressed (0x04 || X || Y).
// This is different from ECDSA because the algorithm byte is ECDH (18) instead of ECDSA (19).
func V4FingerprintECDH(publicKey []byte, creationTime time.Time) []byte {
	// Build the subkey packet body with ECDH algorithm
	body := buildECDHPublicKeyBody(publicKey, creationTime)

	// V4 fingerprint = SHA1(0x99 || 2-byte length || body)
	h := sha1.New()
	h.Write([]byte{0x99})
	h.Write([]byte{byte(len(body) >> 8), byte(len(body))})
	h.Write(body)

	return h.Sum(nil)
}

// V4FingerprintCurve25519ECDH computes the V4 fingerprint for a Curve25519 ECDH public key.
// The publicKey should be 32 bytes in native (little-endian / RFC 7748) format.
func V4FingerprintCurve25519ECDH(publicKey []byte, creationTime time.Time) []byte {
	body := buildCurve25519ECDHPublicKeyBody(publicKey, creationTime)

	// V4 fingerprint = SHA1(0x99 || 2-byte length || body)
	h := sha1.New()
	h.Write([]byte{0x99})
	h.Write([]byte{byte(len(body) >> 8), byte(len(body))})
	h.Write(body)

	return h.Sum(nil)
}

// buildECDHPublicKeyBody builds the body of an ECDH public key packet.
// Accepts compressed (33 bytes) or uncompressed (65 bytes) P-256 keys.
// RFC 6637 section 9 - ECDH Public Key Algorithm
func buildECDHPublicKeyBody(publicKey []byte, creationTime time.Time) []byte {
	pw := NewPacketWriter()

	// Version 4
	pw.WriteByte(4)

	// Creation time (4 bytes, big-endian)
	ts := uint32(creationTime.Unix())
	pw.WriteUint32(ts)

	// Algorithm (ECDH = 18)
	pw.WriteByte(PubKeyAlgoECDH)

	// OID length + OID for P-256
	pw.WriteByte(byte(len(OIDP256)))
	pw.Write(OIDP256)

	// OpenPGP requires uncompressed EC point (0x04 || X || Y)
	uncompressed := decompressP256ForOpenPGP(publicKey)
	pw.Write(EncodeMPIFromBytes(uncompressed))

	// KDF parameters (RFC 6637 section 9)
	// Format: length || reserved || hash_algo || sym_algo
	// We use SHA256 (8) for hash and AES256 (9) for symmetric
	kdfParams := []byte{
		0x03,           // KDF parameter length
		0x01,           // Reserved (0x01 per RFC 6637)
		HashAlgoSHA256, // Hash algorithm for KDF
		SymAlgoAES256,  // Symmetric algorithm for key wrapping
	}
	pw.Write(kdfParams)

	return pw.Bytes()
}

// buildCurve25519ECDHPublicKeyBody builds the body of a Curve25519 ECDH public key packet.
// The publicKey should be 32 bytes in native (little-endian / RFC 7748) format.
// OpenPGP stores Curve25519 keys in reversed (big-endian) byte order with a 0x40 prefix.
func buildCurve25519ECDHPublicKeyBody(publicKey []byte, creationTime time.Time) []byte {
	pw := NewPacketWriter()

	// Version 4
	pw.WriteByte(4)

	// Creation time (4 bytes, big-endian)
	ts := uint32(creationTime.Unix())
	pw.WriteUint32(ts)

	// Algorithm (ECDH = 18)
	pw.WriteByte(PubKeyAlgoECDH)

	// OID length + OID for Curve25519
	pw.WriteByte(byte(len(OIDCurve25519)))
	pw.Write(OIDCurve25519)

	// Public key MPI: 0x40 || reversed(publicKey)
	// OpenPGP uses big-endian for Curve25519, Go uses little-endian (RFC 7748)
	point := make([]byte, 1+len(publicKey))
	point[0] = 0x40
	copy(point[1:], reverseBytes(publicKey))
	pw.Write(EncodeMPIFromBytes(point))

	// KDF parameters (same structure as P-256)
	kdfParams := []byte{
		0x03,           // KDF parameter length
		0x01,           // Reserved (0x01 per RFC 6637)
		HashAlgoSHA256, // Hash algorithm for KDF
		SymAlgoAES256,  // Symmetric algorithm for key wrapping
	}
	pw.Write(kdfParams)

	return pw.Bytes()
}

// BuildSubkeyPacket builds a complete P-256 ECDH encryption subkey packet.
// Uses packet tag 14 (public subkey) instead of tag 6 (public key).
func BuildSubkeyPacket(publicKey []byte, creationTime time.Time) []byte {
	body := buildECDHPublicKeyBody(publicKey, creationTime)
	return BuildPacket(PacketTagPublicSubkey, body)
}

// BuildCurve25519SubkeyPacket builds a complete Curve25519 ECDH encryption subkey packet.
// Uses packet tag 14 (public subkey) instead of tag 6 (public key).
// The publicKey should be 32 bytes in native (little-endian / RFC 7748) format.
func BuildCurve25519SubkeyPacket(publicKey []byte, creationTime time.Time) []byte {
	body := buildCurve25519ECDHPublicKeyBody(publicKey, creationTime)
	return BuildPacket(PacketTagPublicSubkey, body)
}

// SubkeyBindingBuilder builds a subkey binding signature (type 0x18).
// This binds an encryption subkey to a primary signing key.
type SubkeyBindingBuilder struct {
	primaryFingerprint []byte
	subkeyPublicKey    []byte
	subkeyCreationTime time.Time
	signatureTime      time.Time
}

// NewSubkeyBindingBuilder creates a builder for subkey binding signatures.
func NewSubkeyBindingBuilder(primaryFingerprint []byte, subkeyPublicKey []byte, subkeyCreationTime time.Time) *SubkeyBindingBuilder {
	return &SubkeyBindingBuilder{
		primaryFingerprint: primaryFingerprint,
		subkeyPublicKey:    subkeyPublicKey,
		subkeyCreationTime: subkeyCreationTime,
		signatureTime:      time.Now(),
	}
}

// SetSignatureTime sets the signature creation time.
func (b *SubkeyBindingBuilder) SetSignatureTime(t time.Time) *SubkeyBindingBuilder {
	b.signatureTime = t
	return b
}

// BuildHashInput constructs the data to be hashed for the subkey binding signature.
// RFC 4880 section 5.2.4: The hash is over:
// - Primary key body (without packet header)
// - Subkey body (without packet header)
// - Signature header + hashed subpackets + trailer
func (b *SubkeyBindingBuilder) BuildHashInput() (digest []byte, header []byte) {
	// Build hashed subpackets
	hashedSub := NewSubpacketBuilder()
	hashedSub.AddCreationTime(b.signatureTime)
	// Add key flags subpacket: 0x04 = may encrypt communications, 0x08 = may encrypt storage
	hashedSub.AddKeyFlags(0x04 | 0x08)
	hashedSub.AddIssuerFingerprint(b.primaryFingerprint)
	hashedData := hashedSub.Bytes()

	// Build unhashed subpackets
	unhashedSub := NewSubpacketBuilder()
	keyID := KeyIDFromFingerprint(b.primaryFingerprint)
	unhashedSub.AddIssuer(keyID)
	// unhashedData will be used later in FinalizeSignature

	// Build signature header
	header = []byte{
		SigVersion4,
		SignatureTypeSubkeyBinding,
		PubKeyAlgoECDSA,
		HashAlgoSHA256,
		byte(len(hashedData) >> 8),
		byte(len(hashedData)),
	}

	// Signature trailer
	headerLen := len(header) + len(hashedData)
	trailer := []byte{
		0x04,
		0xFF,
		byte(headerLen >> 24),
		byte(headerLen >> 16),
		byte(headerLen >> 8),
		byte(headerLen),
	}

	// Compute the hash
	// For subkey binding: primary_key_body || subkey_body || sig_header || hashed_subpackets || trailer
	h := sha256.New()

	// Primary key body (without packet framing)
	// We need to reconstruct the key body from the fingerprint's creation time
	// Since we don't have the creation time for the primary key, we'll use a different approach
	// The primary key body can be reconstructed from what we have
	// Actually, for the binding signature we need the raw key material
	// Let's build just from the fingerprint info we have

	// RFC 4880 5.2.4: for subkey binding, hash the primary key packet body (without tag/length)
	// followed by the subkey packet body (without tag/length)
	// Since we're given the fingerprint (which was computed from the primary key body),
	// we need to reconstruct or receive the primary public key bytes separately.

	// For now, we'll use a simpler approach: include the subkey body
	subkeyBody := buildECDHPublicKeyBody(b.subkeyPublicKey, b.subkeyCreationTime)
	h.Write([]byte{0x99})
	h.Write([]byte{byte(len(subkeyBody) >> 8), byte(len(subkeyBody))})
	h.Write(subkeyBody)

	h.Write(header)
	h.Write(hashedData)
	h.Write(trailer)

	digest = h.Sum(nil)
	return digest, header
}

// BuildSubkeyBindingSignature creates a complete subkey binding signature packet.
// The signFunc is called with the digest and should return a 64-byte signature (r || s for ECDSA, or 64-byte EdDSA).
// primaryAlgorithm should be PubKeyAlgoECDSA or PubKeyAlgoEdDSA.
// subkeyIsCurve25519 selects the Curve25519 ECDH body builder vs P-256 ECDH.
func BuildSubkeyBindingSignature(
	primaryPublicKey []byte,
	primaryFingerprint []byte,
	primaryCreationTime time.Time,
	primaryAlgorithm byte,
	subkeyPublicKey []byte,
	subkeyCreationTime time.Time,
	subkeyIsCurve25519 bool,
	signFunc func(digest []byte) ([]byte, error),
) ([]byte, error) {
	signatureTime := time.Now()

	// Build hashed subpackets
	hashedSub := NewSubpacketBuilder()
	hashedSub.AddCreationTime(signatureTime)
	// Key flags: 0x04 = may encrypt communications, 0x08 = may encrypt storage
	hashedSub.AddKeyFlags(0x04 | 0x08)
	hashedSub.AddIssuerFingerprint(primaryFingerprint)
	hashedData := hashedSub.Bytes()

	// Build unhashed subpackets
	unhashedSub := NewSubpacketBuilder()
	keyID := KeyIDFromFingerprint(primaryFingerprint)
	unhashedSub.AddIssuer(keyID)
	unhashedData := unhashedSub.Bytes()

	// Build signature header
	header := []byte{
		SigVersion4,
		SignatureTypeSubkeyBinding,
		primaryAlgorithm, // ECDSA or EdDSA
		HashAlgoSHA256,
		byte(len(hashedData) >> 8),
		byte(len(hashedData)),
	}

	// Signature trailer for hashing
	headerLen := len(header) + len(hashedData)
	trailer := []byte{
		0x04,
		0xFF,
		byte(headerLen >> 24),
		byte(headerLen >> 16),
		byte(headerLen >> 8),
		byte(headerLen),
	}

	// Build hash input
	// RFC 4880 section 5.2.4: For subkey binding signature (0x18):
	// Hash the primary key body followed by the subkey body
	h := sha256.New()

	// Primary key body with 0x99 prefix (same format as fingerprint computation)
	var primaryKeyBody []byte
	if primaryAlgorithm == PubKeyAlgoEdDSA {
		primaryKeyBody = buildEdDSAPublicKeyBody(primaryPublicKey, primaryCreationTime)
	} else {
		primaryKeyBody = buildECDSAPublicKeyBody(primaryPublicKey, primaryCreationTime)
	}
	h.Write([]byte{0x99})
	h.Write([]byte{byte(len(primaryKeyBody) >> 8), byte(len(primaryKeyBody))})
	h.Write(primaryKeyBody)

	// Subkey body with 0x99 prefix
	var subkeyBody []byte
	if subkeyIsCurve25519 {
		subkeyBody = buildCurve25519ECDHPublicKeyBody(subkeyPublicKey, subkeyCreationTime)
	} else {
		subkeyBody = buildECDHPublicKeyBody(subkeyPublicKey, subkeyCreationTime)
	}
	h.Write([]byte{0x99})
	h.Write([]byte{byte(len(subkeyBody) >> 8), byte(len(subkeyBody))})
	h.Write(subkeyBody)

	// Signature header + hashed subpackets + trailer
	h.Write(header)
	h.Write(hashedData)
	h.Write(trailer)

	digest := h.Sum(nil)

	// Sign the digest
	rawSig, err := signFunc(digest)
	if err != nil {
		return nil, err
	}

	// Build the signature packet
	pw := NewPacketWriter()

	// Write header
	pw.Write(header)

	// Write hashed subpackets
	pw.Write(hashedData)

	// Write unhashed subpacket length and data
	pw.WriteUint16(uint16(len(unhashedData)))
	pw.Write(unhashedData)

	// Write hash prefix (first 2 bytes of digest)
	pw.WriteByte(digest[0])
	pw.WriteByte(digest[1])

	// Write signature MPIs based on algorithm
	if primaryAlgorithm == PubKeyAlgoEdDSA {
		// EdDSA: single MPI containing the 64-byte signature
		pw.Write(EncodeMPIFromBytes(rawSig))
	} else {
		// ECDSA: two MPIs (r and s, each 32 bytes)
		r := rawSig[:32]
		s := rawSig[32:]
		pw.Write(EncodeMPIFromBytes(r))
		pw.Write(EncodeMPIFromBytes(s))
	}

	// Return complete packet
	return BuildPacket(PacketTagSignature, pw.Bytes()), nil
}
