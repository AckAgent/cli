package openpgp

import (
	"crypto/sha256"
	"time"
)

// CertificationBuilder builds self-certification signatures (type 0x13) for User IDs.
// Per RFC 4880 §5.2.4, a positive certification signature binds a User ID to a key.
type CertificationBuilder struct {
	primaryPublicKey    []byte
	primaryCreationTime time.Time
	userID              string
	signatureTime       time.Time
	pubKeyAlgo          byte
	keyFlags            byte
}

// NewCertificationBuilder creates a builder for User ID certification signatures.
// primaryPublicKey should be 64 bytes for P-256 ECDSA or 32 bytes for Ed25519.
func NewCertificationBuilder(primaryPublicKey []byte, primaryCreationTime time.Time, userID string) *CertificationBuilder {
	// Default to P-256 ECDSA
	algo := byte(PubKeyAlgoECDSA)
	if len(primaryPublicKey) == 32 {
		algo = PubKeyAlgoEdDSA
	}
	return &CertificationBuilder{
		primaryPublicKey:    primaryPublicKey,
		primaryCreationTime: primaryCreationTime,
		userID:              userID,
		signatureTime:       time.Now(),
		pubKeyAlgo:          algo,
		keyFlags:            0x03, // May certify (0x01) + May sign (0x02)
	}
}

// SetSignatureTime sets the signature creation time.
func (b *CertificationBuilder) SetSignatureTime(t time.Time) *CertificationBuilder {
	b.signatureTime = t
	return b
}

// SetKeyFlags sets the key capability flags.
// Common flags: 0x01=certify, 0x02=sign, 0x04=encrypt communications, 0x08=encrypt storage
func (b *CertificationBuilder) SetKeyFlags(flags byte) *CertificationBuilder {
	b.keyFlags = flags
	return b
}

// BuildHashInput constructs the data to be hashed for the self-certification signature.
// Returns the SHA-256 digest and the signature header (for packet assembly).
//
// Per RFC 4880 §5.2.4, for certification signatures (types 0x10-0x13):
// Hash input = 0x99 || primaryKeyLen || primaryKeyBody ||
//
//	0xB4 || userIDLen || userID ||
//	sigHeader || hashedSubpackets || trailer
func (b *CertificationBuilder) BuildHashInput() (digest []byte, header []byte, hashedData []byte, unhashedData []byte) {
	// Build the primary key body based on algorithm
	var primaryKeyBody []byte
	if b.pubKeyAlgo == PubKeyAlgoEdDSA {
		primaryKeyBody = buildEdDSAPublicKeyBody(b.primaryPublicKey, b.primaryCreationTime)
	} else {
		primaryKeyBody = buildECDSAPublicKeyBody(b.primaryPublicKey, b.primaryCreationTime)
	}

	// Compute fingerprint for issuer subpackets
	var fingerprint []byte
	if b.pubKeyAlgo == PubKeyAlgoEdDSA {
		fingerprint = V4FingerprintEd25519(b.primaryPublicKey, b.primaryCreationTime)
	} else {
		fingerprint = V4Fingerprint(b.primaryPublicKey, b.primaryCreationTime)
	}

	// Build hashed subpackets
	hashedSub := NewSubpacketBuilder()
	hashedSub.AddCreationTime(b.signatureTime)
	hashedSub.AddKeyFlags(b.keyFlags)
	hashedSub.AddIssuerFingerprint(fingerprint)
	hashedData = hashedSub.Bytes()

	// Build unhashed subpackets
	unhashedSub := NewSubpacketBuilder()
	keyID := KeyIDFromFingerprint(fingerprint)
	unhashedSub.AddIssuer(keyID)
	unhashedData = unhashedSub.Bytes()

	// Build signature header
	header = []byte{
		SigVersion4,
		SigTypePositiveCertification,
		b.pubKeyAlgo,
		HashAlgoSHA256,
		byte(len(hashedData) >> 8),
		byte(len(hashedData)),
	}

	// Signature trailer for hashing
	// 0x04 || 0xFF || 4-byte length of header + hashed subpackets
	headerLen := len(header) + len(hashedData)
	trailer := []byte{
		0x04,
		0xFF,
		byte(headerLen >> 24),
		byte(headerLen >> 16),
		byte(headerLen >> 8),
		byte(headerLen),
	}

	// Build the hash
	h := sha256.New()

	// Primary key with 0x99 prefix (same format as fingerprint computation)
	h.Write([]byte{0x99})
	h.Write([]byte{byte(len(primaryKeyBody) >> 8), byte(len(primaryKeyBody))})
	h.Write(primaryKeyBody)

	// User ID with 0xB4 prefix and 4-byte length
	userIDBytes := []byte(b.userID)
	h.Write([]byte{0xB4})
	h.Write([]byte{
		byte(len(userIDBytes) >> 24),
		byte(len(userIDBytes) >> 16),
		byte(len(userIDBytes) >> 8),
		byte(len(userIDBytes)),
	})
	h.Write(userIDBytes)

	// Signature header + hashed subpackets + trailer
	h.Write(header)
	h.Write(hashedData)
	h.Write(trailer)

	digest = h.Sum(nil)
	return digest, header, hashedData, unhashedData
}

// FinalizeCertificationSignature creates a complete certification signature packet
// from the pre-computed components and a raw signature.
// For ECDSA: rawSig should be 64 bytes (r || s).
// For EdDSA: rawSig should be 64 bytes (Ed25519 signature).
func FinalizeCertificationSignature(header, hashedData, unhashedData, digest, rawSig []byte, pubKeyAlgo byte) []byte {
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
	if pubKeyAlgo == PubKeyAlgoEdDSA {
		// EdDSA: single MPI containing the 64-byte signature
		pw.Write(EncodeMPIFromBytes(rawSig))
	} else {
		// ECDSA: two MPIs (r and s)
		r := rawSig[:32]
		s := rawSig[32:]
		pw.Write(EncodeMPIFromBytes(r))
		pw.Write(EncodeMPIFromBytes(s))
	}

	// Return complete packet
	return BuildPacket(PacketTagSignature, pw.Bytes())
}

// BuildCertificationHashInput is a convenience function that builds the hash input
// for a User ID certification signature.
// Returns the digest that should be signed, plus components needed to finalize the signature.
func BuildCertificationHashInput(
	primaryPublicKey []byte,
	primaryCreationTime time.Time,
	userID string,
	signatureTime time.Time,
) (digest, header, hashedData, unhashedData []byte, pubKeyAlgo byte) {
	builder := NewCertificationBuilder(primaryPublicKey, primaryCreationTime, userID)
	builder.SetSignatureTime(signatureTime)
	digest, header, hashedData, unhashedData = builder.BuildHashInput()
	pubKeyAlgo = builder.pubKeyAlgo
	return
}

// BuildSubkeyBindingHashInput builds the hash input for a subkey binding signature (type 0x18).
// This binds an encryption subkey to a primary signing key.
// Returns the digest to be signed, plus components for finalizing the signature.
func BuildSubkeyBindingHashInput(
	primaryPublicKey []byte,
	primaryCreationTime time.Time,
	subkeyPublicKey []byte,
	subkeyCreationTime time.Time,
	signatureTime time.Time,
	pubKeyAlgo byte,
) (digest, header, hashedData, unhashedData []byte) {
	// Build the primary key body
	var primaryKeyBody []byte
	if pubKeyAlgo == PubKeyAlgoEdDSA {
		primaryKeyBody = buildEdDSAPublicKeyBody(primaryPublicKey, primaryCreationTime)
	} else {
		primaryKeyBody = buildECDSAPublicKeyBody(primaryPublicKey, primaryCreationTime)
	}

	// Compute primary key fingerprint
	var primaryFingerprint []byte
	if pubKeyAlgo == PubKeyAlgoEdDSA {
		primaryFingerprint = V4FingerprintEd25519(primaryPublicKey, primaryCreationTime)
	} else {
		primaryFingerprint = V4Fingerprint(primaryPublicKey, primaryCreationTime)
	}

	// Build hashed subpackets
	hashedSub := NewSubpacketBuilder()
	hashedSub.AddCreationTime(signatureTime)
	// Key flags for encryption subkey: 0x04=encrypt communications, 0x08=encrypt storage
	hashedSub.AddKeyFlags(0x04 | 0x08)
	hashedSub.AddIssuerFingerprint(primaryFingerprint)
	hashedData = hashedSub.Bytes()

	// Build unhashed subpackets
	unhashedSub := NewSubpacketBuilder()
	keyID := KeyIDFromFingerprint(primaryFingerprint)
	unhashedSub.AddIssuer(keyID)
	unhashedData = unhashedSub.Bytes()

	// Build signature header
	header = []byte{
		SigVersion4,
		SigTypeSubkeyBinding,
		pubKeyAlgo,
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

	// Build the hash
	h := sha256.New()

	// Primary key with 0x99 prefix
	h.Write([]byte{0x99})
	h.Write([]byte{byte(len(primaryKeyBody) >> 8), byte(len(primaryKeyBody))})
	h.Write(primaryKeyBody)

	// Subkey with 0x99 prefix
	subkeyBody := buildECDHPublicKeyBody(subkeyPublicKey, subkeyCreationTime)
	h.Write([]byte{0x99})
	h.Write([]byte{byte(len(subkeyBody) >> 8), byte(len(subkeyBody))})
	h.Write(subkeyBody)

	// Signature header + hashed subpackets + trailer
	h.Write(header)
	h.Write(hashedData)
	h.Write(trailer)

	digest = h.Sum(nil)
	return
}

// FinalizeBindingSignature creates a complete binding signature packet (0x18).
// Same logic as certification but for subkey binding.
func FinalizeBindingSignature(header, hashedData, unhashedData, digest, rawSig []byte, pubKeyAlgo byte) []byte {
	// Same structure as certification signature
	return FinalizeCertificationSignature(header, hashedData, unhashedData, digest, rawSig, pubKeyAlgo)
}
