package openpgp

import (
	"crypto/sha256"
	"fmt"
	"io"
	"time"
)

// SignatureBuilder builds an OpenPGP V4 signature packet.
type SignatureBuilder struct {
	sigType      byte
	pubKeyAlgo   byte
	hashAlgo     byte
	creationTime time.Time
	issuerKeyID  uint64
	issuerFP     []byte
	hashedData   []byte
	unhashedData []byte
}

// NewSignatureBuilder creates a new signature builder.
func NewSignatureBuilder() *SignatureBuilder {
	return &SignatureBuilder{
		sigType:      SigTypeBinary,
		pubKeyAlgo:   PubKeyAlgoECDSA,
		hashAlgo:     HashAlgoSHA256,
		creationTime: time.Now(),
	}
}

// SetSignatureType sets the signature type.
func (sb *SignatureBuilder) SetSignatureType(sigType byte) *SignatureBuilder {
	sb.sigType = sigType
	return sb
}

// SetCreationTime sets the signature creation time.
func (sb *SignatureBuilder) SetCreationTime(t time.Time) *SignatureBuilder {
	sb.creationTime = t
	return sb
}

// SetIssuerKeyID sets the issuer key ID.
func (sb *SignatureBuilder) SetIssuerKeyID(keyID uint64) *SignatureBuilder {
	sb.issuerKeyID = keyID
	return sb
}

// SetIssuerFingerprint sets the issuer fingerprint (20 bytes for V4).
func (sb *SignatureBuilder) SetIssuerFingerprint(fp []byte) *SignatureBuilder {
	sb.issuerFP = fp
	return sb
}

// SetPubKeyAlgo sets the public key algorithm.
func (sb *SignatureBuilder) SetPubKeyAlgo(algo byte) *SignatureBuilder {
	sb.pubKeyAlgo = algo
	return sb
}

// BuildHashInput constructs the data to be hashed for signing.
// The message data should be hashed before calling this.
// Returns the hash input that should be passed to the signer.
func (sb *SignatureBuilder) BuildHashInput(messageData []byte) ([]byte, []byte) {
	// Build hashed subpackets
	hashedSub := NewSubpacketBuilder()
	hashedSub.AddCreationTime(sb.creationTime)
	if len(sb.issuerFP) > 0 {
		hashedSub.AddIssuerFingerprint(sb.issuerFP)
	}
	sb.hashedData = hashedSub.Bytes()

	// Build unhashed subpackets
	unhashedSub := NewSubpacketBuilder()
	if sb.issuerKeyID != 0 {
		unhashedSub.AddIssuer(sb.issuerKeyID)
	}
	sb.unhashedData = unhashedSub.Bytes()

	// Build signature header (everything before hashed subpacket data)
	header := []byte{
		SigVersion4,
		sb.sigType,
		sb.pubKeyAlgo,
		sb.hashAlgo,
		byte(len(sb.hashedData) >> 8),
		byte(len(sb.hashedData)),
	}

	// Signature trailer for hashing
	// 0x04 || 0xFF || 4-byte length of header + hashed subpackets
	headerLen := len(header) + len(sb.hashedData)
	trailer := []byte{
		0x04,
		0xFF,
		byte(headerLen >> 24),
		byte(headerLen >> 16),
		byte(headerLen >> 8),
		byte(headerLen),
	}

	// Compute hash: message || header || hashed_subpackets || trailer
	h := sha256.New()
	h.Write(messageData)
	h.Write(header)
	h.Write(sb.hashedData)
	h.Write(trailer)
	digest := h.Sum(nil)

	return digest, header
}

// FinalizeSignature creates the complete signature packet given the raw signature.
// For ECDSA: rawSig should be the 64-byte signature (r || s), encoded as two MPIs.
// For EdDSA: rawSig should be the 64-byte Ed25519 signature, encoded as a single MPI.
func (sb *SignatureBuilder) FinalizeSignature(header []byte, digest []byte, rawSig []byte) ([]byte, error) {
	if len(rawSig) != 64 {
		return nil, fmt.Errorf("invalid signature length: expected 64 bytes")
	}

	pw := NewPacketWriter()

	// Write header
	pw.Write(header)

	// Write hashed subpackets
	pw.Write(sb.hashedData)

	// Write unhashed subpacket length and data
	pw.WriteUint16(uint16(len(sb.unhashedData)))
	pw.Write(sb.unhashedData)

	// Write hash prefix (first 2 bytes of digest)
	pw.WriteByte(digest[0])
	pw.WriteByte(digest[1])

	// Write signature MPIs based on algorithm
	if sb.pubKeyAlgo == PubKeyAlgoEdDSA {
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
	return BuildPacket(PacketTagSignature, pw.Bytes()), nil
}

// FixEdDSASignatureMPIs re-encodes the signature MPIs in an EdDSA OpenPGP
// signature packet. Android encodes EdDSA signatures as a single 64-byte MPI
// (R||S combined), but OpenPGP requires two separate MPIs: R (32 bytes) and
// S (32 bytes). Returns the packet unchanged if it already has correct
// encoding or is not EdDSA.
func FixEdDSASignatureMPIs(packet []byte) []byte {
	if len(packet) == 0 {
		return packet
	}

	// Parse the outer packet to get tag and body
	reader := NewPacketReader(packet)
	parsed, err := reader.Next()
	if err != nil || parsed.Tag != PacketTagSignature {
		return packet
	}
	body := parsed.Body

	// Parse V4 signature body structure:
	// version(1) + sigType(1) + pubAlgo(1) + hashAlgo(1) + hashedSubLen(2) + hashedSub(N)
	// + unhashedSubLen(2) + unhashedSub(M) + hashLeft2(2) + MPIs...
	if len(body) < 6 {
		return packet
	}
	if body[0] != SigVersion4 {
		return packet
	}
	pubAlgo := body[2]
	if pubAlgo != PubKeyAlgoEdDSA {
		return packet
	}

	// Skip past fixed header (4 bytes) + hashed subpackets
	offset := 4
	if offset+2 > len(body) {
		return packet
	}
	hashedLen := int(body[offset])<<8 | int(body[offset+1])
	offset += 2 + hashedLen

	// Skip unhashed subpackets
	if offset+2 > len(body) {
		return packet
	}
	unhashedLen := int(body[offset])<<8 | int(body[offset+1])
	offset += 2 + unhashedLen

	// Skip hash left 2
	if offset+2 > len(body) {
		return packet
	}
	offset += 2

	// Now at MPI data — decode first MPI
	if offset >= len(body) {
		return packet
	}
	mpi1, mpi1Consumed, err := DecodeMPI(body, offset)
	if err != nil {
		return packet
	}

	// Check if there's a second MPI (already correct two-MPI format)
	afterFirst := offset + mpi1Consumed
	if afterFirst < len(body) {
		// Try to decode a second MPI
		_, _, err := DecodeMPI(body, afterFirst)
		if err == nil || err != io.EOF {
			// Already has two MPIs — return unchanged
			return packet
		}
	}

	// Single MPI: check if it's ~64 bytes (combined R||S)
	if len(mpi1) != 64 {
		return packet
	}

	// Split into R (first 32) and S (last 32), re-encode as two MPIs
	rMPI := EncodeMPIFromBytes(mpi1[:32])
	sMPI := EncodeMPIFromBytes(mpi1[32:])

	// Rebuild body: everything before MPIs + two new MPIs
	newBody := make([]byte, offset, offset+len(rMPI)+len(sMPI))
	copy(newBody, body[:offset])
	newBody = append(newBody, rMPI...)
	newBody = append(newBody, sMPI...)

	return BuildPacket(PacketTagSignature, newBody)
}
