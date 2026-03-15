package openpgp

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"math/big"
)

// ParsedSignature holds a parsed V4 signature packet.
type ParsedSignature struct {
	Version       byte
	SigType       byte
	PubKeyAlgo    byte
	HashAlgo      byte
	HashedSubData []byte  // raw hashed subpacket area (needed for hash reconstruction)
	IssuerKeyID   uint64  // from subpacket type 16
	IssuerFP      []byte  // 20-byte fingerprint from subpacket type 33
	HashPrefix    [2]byte // first two bytes of the hash
	CreationTime  uint32  // from subpacket type 2
	SignatureR    []byte  // ECDSA r value
	SignatureS    []byte  // ECDSA s value
	EdDSASig      []byte  // EdDSA 64-byte signature
}

// ParseSignaturePacket parses a V4 signature packet body per RFC 4880 §5.2.
func ParseSignaturePacket(body []byte) (*ParsedSignature, error) {
	if len(body) < 6 {
		return nil, fmt.Errorf("signature packet too short: %d bytes", len(body))
	}

	sig := &ParsedSignature{
		Version:    body[0],
		SigType:    body[1],
		PubKeyAlgo: body[2],
		HashAlgo:   body[3],
	}

	if sig.Version != SigVersion4 {
		return nil, fmt.Errorf("unsupported signature version: %d", sig.Version)
	}

	offset := 4

	// Hashed subpacket area
	if offset+2 > len(body) {
		return nil, fmt.Errorf("truncated hashed subpacket length")
	}
	hashedLen := int(body[offset])<<8 | int(body[offset+1])
	offset += 2

	if offset+hashedLen > len(body) {
		return nil, fmt.Errorf("hashed subpackets extend beyond packet: need %d bytes", hashedLen)
	}
	sig.HashedSubData = body[offset : offset+hashedLen]
	offset += hashedLen

	// Parse hashed subpackets for creation time and issuer fingerprint
	if fp, keyID, creationTime, err := ParseSubpacketArea(sig.HashedSubData); err == nil {
		if fp != nil {
			sig.IssuerFP = fp
		}
		if keyID != 0 {
			sig.IssuerKeyID = keyID
		}
		sig.CreationTime = creationTime
	}

	// Unhashed subpacket area
	if offset+2 > len(body) {
		return nil, fmt.Errorf("truncated unhashed subpacket length")
	}
	unhashedLen := int(body[offset])<<8 | int(body[offset+1])
	offset += 2

	if offset+unhashedLen > len(body) {
		return nil, fmt.Errorf("unhashed subpackets extend beyond packet")
	}

	// Parse unhashed subpackets for issuer key ID (if not found in hashed)
	unhashedData := body[offset : offset+unhashedLen]
	if fp, keyID, _, err := ParseSubpacketArea(unhashedData); err == nil {
		if sig.IssuerFP == nil && fp != nil {
			sig.IssuerFP = fp
		}
		if sig.IssuerKeyID == 0 && keyID != 0 {
			sig.IssuerKeyID = keyID
		}
	}
	offset += unhashedLen

	// Hash prefix (2 bytes)
	if offset+2 > len(body) {
		return nil, fmt.Errorf("truncated hash prefix")
	}
	sig.HashPrefix[0] = body[offset]
	sig.HashPrefix[1] = body[offset+1]
	offset += 2

	// Signature MPIs
	switch sig.PubKeyAlgo {
	case PubKeyAlgoECDSA:
		// Two MPIs: r and s
		r, consumed, err := DecodeMPI(body, offset)
		if err != nil {
			return nil, fmt.Errorf("failed to decode signature r: %w", err)
		}
		sig.SignatureR = r
		offset += consumed

		s, _, err := DecodeMPI(body, offset)
		if err != nil {
			return nil, fmt.Errorf("failed to decode signature s: %w", err)
		}
		sig.SignatureS = s

	case PubKeyAlgoEdDSA:
		// Single MPI containing the 64-byte signature.
		// MPI encoding strips leading zero bytes, so pad back to 64 bytes.
		raw, _, err := DecodeMPI(body, offset)
		if err != nil {
			return nil, fmt.Errorf("failed to decode EdDSA signature: %w", err)
		}
		if len(raw) < 64 {
			padded := make([]byte, 64)
			copy(padded[64-len(raw):], raw)
			raw = padded
		}
		sig.EdDSASig = raw

	default:
		return nil, fmt.Errorf("unsupported public key algorithm: %d", sig.PubKeyAlgo)
	}

	return sig, nil
}

// ParseSubpacketArea walks subpackets to extract issuer fingerprint, key ID, and creation time.
func ParseSubpacketArea(data []byte) (issuerFP []byte, issuerKeyID uint64, creationTime uint32, err error) {
	pos := 0
	for pos < len(data) {
		// Read subpacket length
		if pos >= len(data) {
			break
		}
		var subLen int
		first := data[pos]
		pos++

		if first < 192 {
			subLen = int(first)
		} else if first < 255 {
			if pos >= len(data) {
				return nil, 0, 0, fmt.Errorf("truncated subpacket length")
			}
			second := data[pos]
			pos++
			subLen = ((int(first) - 192) << 8) + int(second) + 192
		} else {
			// 5-byte length
			if pos+4 > len(data) {
				return nil, 0, 0, fmt.Errorf("truncated subpacket length")
			}
			subLen = int(data[pos])<<24 | int(data[pos+1])<<16 | int(data[pos+2])<<8 | int(data[pos+3])
			pos += 4
		}

		if subLen < 1 || pos+subLen > len(data) {
			return nil, 0, 0, fmt.Errorf("invalid subpacket length: %d at pos %d", subLen, pos)
		}

		// Type byte (strip critical bit)
		subType := data[pos] & 0x7F
		subBody := data[pos+1 : pos+subLen]
		pos += subLen

		switch subType {
		case SubpacketSignatureCreationTime:
			if len(subBody) >= 4 {
				creationTime = uint32(subBody[0])<<24 | uint32(subBody[1])<<16 | uint32(subBody[2])<<8 | uint32(subBody[3])
			}
		case SubpacketIssuer:
			if len(subBody) >= 8 {
				for _, b := range subBody[:8] {
					issuerKeyID = (issuerKeyID << 8) | uint64(b)
				}
			}
		case SubpacketIssuerFingerprint:
			if len(subBody) >= 21 && subBody[0] == 4 {
				issuerFP = subBody[1:21]
			}
		}
	}
	return issuerFP, issuerKeyID, creationTime, nil
}

// VerifyDetached verifies a detached signature against the signed data.
// pubKey is the raw public key bytes (65 bytes uncompressed for P-256, 32 bytes for Ed25519).
// isEd25519 indicates whether this is an Ed25519 key.
func VerifyDetached(pubKey []byte, isEd25519 bool, data []byte, sig *ParsedSignature) error {
	if sig.HashAlgo != HashAlgoSHA256 {
		return fmt.Errorf("unsupported hash algorithm: %d", sig.HashAlgo)
	}

	// Reconstruct the hash input per RFC 4880 §5.2.4
	// header = version || sigType || pubKeyAlgo || hashAlgo || hashedSubLen
	hashedSubLen := len(sig.HashedSubData)
	header := []byte{
		sig.Version,
		sig.SigType,
		sig.PubKeyAlgo,
		sig.HashAlgo,
		byte(hashedSubLen >> 8),
		byte(hashedSubLen),
	}

	// trailer = 0x04 || 0xFF || 4-byte big-endian length of (header + hashedSubData)
	headerLen := len(header) + hashedSubLen
	trailer := []byte{
		0x04,
		0xFF,
		byte(headerLen >> 24),
		byte(headerLen >> 16),
		byte(headerLen >> 8),
		byte(headerLen),
	}

	// Compute digest = SHA256(data || header || hashedSubData || trailer)
	h := sha256.New()
	h.Write(data)
	h.Write(header)
	h.Write(sig.HashedSubData)
	h.Write(trailer)
	digest := h.Sum(nil)

	// Check hash prefix
	if digest[0] != sig.HashPrefix[0] || digest[1] != sig.HashPrefix[1] {
		return fmt.Errorf("hash prefix mismatch: expected %02X%02X, got %02X%02X",
			sig.HashPrefix[0], sig.HashPrefix[1], digest[0], digest[1])
	}

	if isEd25519 {
		return verifyEd25519(pubKey, digest, sig.EdDSASig)
	}
	return verifyECDSAP256(pubKey, digest, sig.SignatureR, sig.SignatureS)
}

// verifyECDSAP256 verifies an ECDSA P-256 signature.
func verifyECDSAP256(pubKeyBytes []byte, digest []byte, r, s []byte) error {
	// Decompress if needed
	pubKeyBytes = decompressP256ForOpenPGP(pubKeyBytes)

	x, y := elliptic.Unmarshal(elliptic.P256(), pubKeyBytes)
	if x == nil {
		return fmt.Errorf("invalid P-256 public key")
	}

	pubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	rInt := new(big.Int).SetBytes(r)
	sInt := new(big.Int).SetBytes(s)

	if !ecdsa.Verify(pubKey, digest, rInt, sInt) {
		return fmt.Errorf("ECDSA signature verification failed")
	}
	return nil
}

// verifyEd25519 verifies an Ed25519 signature over a hash digest.
// Ed25519 in OpenPGP signs the hash, not the raw message.
func verifyEd25519(pubKeyBytes []byte, digest []byte, edSig []byte) error {
	if len(pubKeyBytes) != 32 {
		return fmt.Errorf("invalid Ed25519 public key length: %d", len(pubKeyBytes))
	}
	if len(edSig) != 64 {
		return fmt.Errorf("invalid Ed25519 signature length: %d", len(edSig))
	}

	pubKey := ed25519.PublicKey(pubKeyBytes)

	// OpenPGP EdDSA signs the hash digest, not the original message.
	// Use ed25519.VerifyWithOptions with HashFunc = crypto.SHA256 (pre-hashed Ed25519ph)
	// Actually, RFC 4880bis EdDSA uses "pure" Ed25519 over the hash digest.
	if !ed25519.Verify(pubKey, digest, edSig) {
		return fmt.Errorf("Ed25519 signature verification failed")
	}
	return nil
}
