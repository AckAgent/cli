package crypto

import (
	"crypto/elliptic"
	"fmt"
	"math/big"
)

// CompressP256PublicKey compresses a P-256 public key to SEC1 compressed format (33 bytes).
// Accepts 33-byte compressed (returned as-is after validation), 64-byte raw (X || Y),
// or 65-byte uncompressed (0x04 || X || Y) input.
func CompressP256PublicKey(key []byte) ([]byte, error) {
	switch len(key) {
	case PublicKeySize: // 33 bytes — already compressed
		x, y := elliptic.UnmarshalCompressed(elliptic.P256(), key)
		if x == nil || y == nil {
			return nil, fmt.Errorf("invalid 33-byte compressed P-256 public key")
		}
		return key, nil

	case UncompressedPublicKeySize: // 65 bytes — uncompressed 0x04 || X || Y
		if key[0] != 0x04 {
			return nil, fmt.Errorf("invalid uncompressed P-256 prefix: expected 0x04, got 0x%02x", key[0])
		}
		x := new(big.Int).SetBytes(key[1:33])
		y := new(big.Int).SetBytes(key[33:65])
		if !elliptic.P256().IsOnCurve(x, y) {
			return nil, fmt.Errorf("invalid P-256 point: not on curve")
		}
		return elliptic.MarshalCompressed(elliptic.P256(), x, y), nil

	case UncompressedPublicKeySize - 1: // 64 bytes — raw X || Y
		x := new(big.Int).SetBytes(key[:32])
		y := new(big.Int).SetBytes(key[32:64])
		if !elliptic.P256().IsOnCurve(x, y) {
			return nil, fmt.Errorf("invalid raw P-256 point: not on curve")
		}
		return elliptic.MarshalCompressed(elliptic.P256(), x, y), nil

	default:
		return nil, fmt.Errorf("P-256 public key must be 33, 64, or 65 bytes, got %d", len(key))
	}
}

// DecompressP256PublicKey decompresses a 33-byte compressed P-256 public key to
// 65-byte uncompressed format (0x04 || X || Y).
func DecompressP256PublicKey(compressed []byte) ([]byte, error) {
	if len(compressed) != PublicKeySize {
		return nil, fmt.Errorf("compressed P-256 key must be %d bytes, got %d", PublicKeySize, len(compressed))
	}
	if compressed[0] != 0x02 && compressed[0] != 0x03 {
		return nil, fmt.Errorf("invalid compressed P-256 prefix: expected 0x02/0x03, got 0x%02x", compressed[0])
	}

	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), compressed)
	if x == nil || y == nil {
		return nil, fmt.Errorf("invalid compressed P-256 public key: decompression failed")
	}

	return elliptic.Marshal(elliptic.P256(), x, y), nil
}

// NormalizeLowS ensures the S value of an ECDSA signature is in the lower half
// of the curve order, preventing signature malleability.
func NormalizeLowS(s *big.Int, curve elliptic.Curve) *big.Int {
	n := curve.Params().N
	halfN := new(big.Int).Rsh(n, 1)
	if s.Cmp(halfN) > 0 {
		s = new(big.Int).Sub(n, s)
	}
	return s
}
