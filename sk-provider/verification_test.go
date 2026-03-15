package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"
)

// TestSSHSignatureVerification performs end-to-end signature verification.
// This simulates what iOS does (sign the SSH SK message) and verifies the signature.
func TestSSHSignatureVerification(t *testing.T) {
	vectors := loadProtocolVectors(t)

	// Load the test private key
	d := new(big.Int)
	d.SetString(vectors.TestKey.PrivateKeyDHex, 16)

	// Load the test public key
	x := new(big.Int)
	x.SetString(vectors.TestKey.PublicKeyXHex, 16)
	y := new(big.Int)
	y.SetString(vectors.TestKey.PublicKeyYHex, 16)

	privateKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		},
		D: d,
	}

	for _, tc := range vectors.SSHSK.MessageConstruction {
		t.Run(tc.Description, func(t *testing.T) {
			// Build the SSH SK message
			data := mustDecodeHex(t, tc.DataHex)
			msg := BuildSSHSKMessage(tc.Application, data, tc.Flags, tc.Counter)

			// Hash the message (ECDSA signs the hash)
			hash := sha256.Sum256(msg)

			// Sign the message (simulating what iOS does)
			r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
			if err != nil {
				t.Fatalf("failed to sign: %v", err)
			}

			// Verify the signature
			if !ecdsa.Verify(&privateKey.PublicKey, hash[:], r, s) {
				t.Error("signature verification failed")
			}

			// Verify signature components are 32 bytes each (P-256)
			rBytes := r.Bytes()
			sBytes := s.Bytes()

			// Pad to 32 bytes if needed
			if len(rBytes) < 32 {
				padded := make([]byte, 32)
				copy(padded[32-len(rBytes):], rBytes)
				rBytes = padded
			}
			if len(sBytes) < 32 {
				padded := make([]byte, 32)
				copy(padded[32-len(sBytes):], sBytes)
				sBytes = padded
			}

			if len(rBytes) != 32 {
				t.Errorf("r length: got %d, want 32", len(rBytes))
			}
			if len(sBytes) != 32 {
				t.Errorf("s length: got %d, want 32", len(sBytes))
			}

			// Verify raw signature format (r || s = 64 bytes)
			rawSig := append(rBytes, sBytes...)
			if len(rawSig) != 64 {
				t.Errorf("raw signature length: got %d, want 64", len(rawSig))
			}

			t.Logf("Signed %s: sig=%s...", tc.Description, hex.EncodeToString(rawSig[:16]))
		})
	}
}

// TestSSHSignatureFromRawBytes tests parsing and verifying a signature from raw bytes.
func TestSSHSignatureFromRawBytes(t *testing.T) {
	vectors := loadProtocolVectors(t)

	// Load the test public key
	x := new(big.Int)
	x.SetString(vectors.TestKey.PublicKeyXHex, 16)
	y := new(big.Int)
	y.SetString(vectors.TestKey.PublicKeyYHex, 16)

	pubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	// Load test private key for signing
	d := new(big.Int)
	d.SetString(vectors.TestKey.PrivateKeyDHex, 16)
	privateKey := &ecdsa.PrivateKey{
		PublicKey: *pubKey,
		D:         d,
	}

	for _, tc := range vectors.SSHSK.MessageConstruction {
		t.Run(tc.Description, func(t *testing.T) {
			// Build message and hash it
			data := mustDecodeHex(t, tc.DataHex)
			msg := BuildSSHSKMessage(tc.Application, data, tc.Flags, tc.Counter)
			hash := sha256.Sum256(msg)

			// Sign
			r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
			if err != nil {
				t.Fatalf("failed to sign: %v", err)
			}

			// Convert to raw signature format (r || s)
			rawSig := make([]byte, 64)
			rBytes := r.Bytes()
			sBytes := s.Bytes()
			copy(rawSig[32-len(rBytes):32], rBytes)
			copy(rawSig[64-len(sBytes):], sBytes)

			// Parse raw signature back to r, s
			parsedR := new(big.Int).SetBytes(rawSig[:32])
			parsedS := new(big.Int).SetBytes(rawSig[32:])

			// Verify with parsed values
			if !ecdsa.Verify(pubKey, hash[:], parsedR, parsedS) {
				t.Error("verification of parsed signature failed")
			}
		})
	}
}

// TestDeterministicMessageConstruction verifies that message construction is deterministic.
func TestDeterministicMessageConstruction(t *testing.T) {
	app := "ssh:"
	data := []byte("test data")
	flags := uint8(1)
	counter := uint32(1)

	// Build the same message multiple times
	msg1 := BuildSSHSKMessage(app, data, flags, counter)
	msg2 := BuildSSHSKMessage(app, data, flags, counter)
	msg3 := BuildSSHSKMessage(app, data, flags, counter)

	// All should be identical
	if hex.EncodeToString(msg1) != hex.EncodeToString(msg2) {
		t.Error("message construction is not deterministic (msg1 != msg2)")
	}
	if hex.EncodeToString(msg2) != hex.EncodeToString(msg3) {
		t.Error("message construction is not deterministic (msg2 != msg3)")
	}
}

// TestSignatureFormatMatchesiOSExpectations verifies the signature format matches
// what sk_provider expects when parsing iOS responses.
func TestSignatureFormatMatchesiOSExpectations(t *testing.T) {
	vectors := loadProtocolVectors(t)

	// Load keys
	d := new(big.Int)
	d.SetString(vectors.TestKey.PrivateKeyDHex, 16)
	x := new(big.Int)
	x.SetString(vectors.TestKey.PublicKeyXHex, 16)
	y := new(big.Int)
	y.SetString(vectors.TestKey.PublicKeyYHex, 16)

	privateKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		},
		D: d,
	}

	// Use first test case
	tc := vectors.SSHSK.MessageConstruction[0]
	data := mustDecodeHex(t, tc.DataHex)
	msg := BuildSSHSKMessage(tc.Application, data, tc.Flags, tc.Counter)
	hash := sha256.Sum256(msg)

	// Sign
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	// Convert to iOS format (padded 32-byte r || s)
	rawSig := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(rawSig[32-len(rBytes):32], rBytes)
	copy(rawSig[64-len(sBytes):], sBytes)

	// Simulate sk_provider parsing (lines 507-540 in sk_provider.go)
	// The sk_provider splits the 64-byte signature into r (first 32) and s (last 32)
	sigR := rawSig[:32]
	sigS := rawSig[32:]

	if len(sigR) != 32 {
		t.Errorf("sig_r length after split: got %d, want 32", len(sigR))
	}
	if len(sigS) != 32 {
		t.Errorf("sig_s length after split: got %d, want 32", len(sigS))
	}

	// Verify sk_provider would accept this signature
	parsedR := new(big.Int).SetBytes(sigR)
	parsedS := new(big.Int).SetBytes(sigS)

	if !ecdsa.Verify(&privateKey.PublicKey, hash[:], parsedR, parsedS) {
		t.Error("signature verification failed after sk_provider-style parsing")
	}
}
