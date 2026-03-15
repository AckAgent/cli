package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
)

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func padTo32(b []byte) []byte {
	if len(b) >= 32 {
		return b[:32]
	}
	result := make([]byte, 32)
	copy(result[32-len(b):], b)
	return result
}

// signDeterministic uses a deterministic nonce for reproducible signatures.
// This implements RFC 6979 in a simplified way for test vectors.
func signDeterministic(privateKey *ecdsa.PrivateKey, digest []byte) (*big.Int, *big.Int) {
	h := sha256.New()
	h.Write(privateKey.D.Bytes())
	h.Write(digest)
	kBytes := h.Sum(nil)

	k := new(big.Int).SetBytes(kBytes)
	n := privateKey.Curve.Params().N
	k.Mod(k, new(big.Int).Sub(n, big.NewInt(1)))
	k.Add(k, big.NewInt(1))

	x1, _ := privateKey.Curve.ScalarBaseMult(k.Bytes())
	r := new(big.Int).Mod(x1, n)

	e := new(big.Int).SetBytes(digest)
	kInv := new(big.Int).ModInverse(k, n)

	s := new(big.Int).Mul(r, privateKey.D)
	s.Add(s, e)
	s.Mul(s, kInv)
	s.Mod(s, n)

	halfN := new(big.Int).Rsh(n, 1)
	if s.Cmp(halfN) > 0 {
		s.Sub(n, s)
	}

	return r, s
}

func appendSSHString(b, s []byte) []byte {
	length := uint32(len(s))
	b = append(b, byte(length>>24), byte(length>>16), byte(length>>8), byte(length))
	return append(b, s...)
}
