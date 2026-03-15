package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"
)

func TestNormalizeLowS_HighSBecomesLow(t *testing.T) {
	curve := elliptic.P256()
	n := curve.Params().N
	halfN := new(big.Int).Rsh(n, 1)

	// Create a high-S value (greater than N/2)
	highS := new(big.Int).Add(halfN, big.NewInt(1))

	normalized := NormalizeLowS(highS, curve)

	if normalized.Cmp(halfN) > 0 {
		t.Errorf("normalized S is still high: %s > %s", normalized, halfN)
	}

	// Verify that normalized = N - highS
	expected := new(big.Int).Sub(n, highS)
	if normalized.Cmp(expected) != 0 {
		t.Errorf("normalized S = %s, want %s", normalized, expected)
	}
}

func TestNormalizeLowS_LowSUnchanged(t *testing.T) {
	curve := elliptic.P256()
	halfN := new(big.Int).Rsh(curve.Params().N, 1)

	// Create a low-S value (less than N/2)
	lowS := new(big.Int).Sub(halfN, big.NewInt(1))
	original := new(big.Int).Set(lowS)

	normalized := NormalizeLowS(lowS, curve)

	if normalized.Cmp(original) != 0 {
		t.Errorf("low-S value was changed: got %s, want %s", normalized, original)
	}
}

func TestNormalizeLowS_ExactHalfOrderUnchanged(t *testing.T) {
	curve := elliptic.P256()
	halfN := new(big.Int).Rsh(curve.Params().N, 1)
	original := new(big.Int).Set(halfN)

	normalized := NormalizeLowS(halfN, curve)

	if normalized.Cmp(original) != 0 {
		t.Errorf("S at exactly N/2 was changed: got %s, want %s", normalized, original)
	}
}

func TestVerifyAttestationSignature_HighSSignatureVerifies(t *testing.T) {
	// Generate a P-256 key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	curve := elliptic.P256()
	n := curve.Params().N
	halfN := new(big.Int).Rsh(n, 1)

	// Create test data
	requestID := make([]byte, 16)
	if _, err := rand.Read(requestID); err != nil {
		t.Fatalf("failed to generate request ID: %v", err)
	}

	encryptedResponse := []byte("test encrypted response data")

	// Build message: requestID || SHA256(encryptedResponse)
	responseHash := sha256.Sum256(encryptedResponse)
	message := make([]byte, len(requestID)+32)
	copy(message, requestID)
	copy(message[len(requestID):], responseHash[:])

	// Hash the message
	msgHash := sha256.Sum256(message)

	// Sign the message and ensure we get a high-S signature
	var sigR, sigS *big.Int
	for attempts := 0; attempts < 100; attempts++ {
		sigR, sigS, err = ecdsa.Sign(rand.Reader, privateKey, msgHash[:])
		if err != nil {
			t.Fatalf("failed to sign: %v", err)
		}
		if sigS.Cmp(halfN) > 0 {
			break // We got a high-S signature
		}
		// If S is low, flip it to high
		sigS = new(big.Int).Sub(n, sigS)
		break
	}

	if sigS.Cmp(halfN) <= 0 {
		t.Fatal("failed to create a high-S signature for testing")
	}

	// Encode as raw r||s signature (64 bytes)
	sigBytes := make([]byte, 64)
	rBytes := sigR.Bytes()
	sBytes := sigS.Bytes()
	copy(sigBytes[32-len(rBytes):32], rBytes)
	copy(sigBytes[64-len(sBytes):64], sBytes)

	// Compress the public key
	compressedPubKey := elliptic.MarshalCompressed(curve, privateKey.PublicKey.X, privateKey.PublicKey.Y)

	// Verify -- this should succeed because normalizeLowS converts high-S to low-S
	valid, err := VerifyAttestationSignature(compressedPubKey, requestID, encryptedResponse, sigBytes)
	if err != nil {
		t.Fatalf("VerifyAttestationSignature returned error: %v", err)
	}
	if !valid {
		t.Error("high-S signature should verify after normalization")
	}
}

func TestVerifyAttestationSignature_LowSSignatureStillVerifies(t *testing.T) {
	// Generate a P-256 key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	curve := elliptic.P256()
	n := curve.Params().N
	halfN := new(big.Int).Rsh(n, 1)

	// Create test data
	requestID := make([]byte, 16)
	if _, err := rand.Read(requestID); err != nil {
		t.Fatalf("failed to generate request ID: %v", err)
	}

	encryptedResponse := []byte("test encrypted response data")

	// Build message: requestID || SHA256(encryptedResponse)
	responseHash := sha256.Sum256(encryptedResponse)
	message := make([]byte, len(requestID)+32)
	copy(message, requestID)
	copy(message[len(requestID):], responseHash[:])

	// Hash the message
	msgHash := sha256.Sum256(message)

	// Sign and ensure low-S
	sigR, sigS, err := ecdsa.Sign(rand.Reader, privateKey, msgHash[:])
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	// Normalize to low-S if needed
	if sigS.Cmp(halfN) > 0 {
		sigS = new(big.Int).Sub(n, sigS)
	}

	if sigS.Cmp(halfN) > 0 {
		t.Fatal("failed to create a low-S signature for testing")
	}

	// Encode as raw r||s signature (64 bytes)
	sigBytes := make([]byte, 64)
	rBytes := sigR.Bytes()
	sBytes := sigS.Bytes()
	copy(sigBytes[32-len(rBytes):32], rBytes)
	copy(sigBytes[64-len(sBytes):64], sBytes)

	// Compress the public key
	compressedPubKey := elliptic.MarshalCompressed(curve, privateKey.PublicKey.X, privateKey.PublicKey.Y)

	// Verify -- low-S signatures should still verify unchanged
	valid, err := VerifyAttestationSignature(compressedPubKey, requestID, encryptedResponse, sigBytes)
	if err != nil {
		t.Fatalf("VerifyAttestationSignature returned error: %v", err)
	}
	if !valid {
		t.Error("low-S signature should verify")
	}
}

func TestNormalizeLowS_DoesNotMutateInput(t *testing.T) {
	curve := elliptic.P256()
	n := curve.Params().N
	halfN := new(big.Int).Rsh(n, 1)

	// Create a high-S value
	highS := new(big.Int).Add(halfN, big.NewInt(42))
	original := new(big.Int).Set(highS)

	_ = NormalizeLowS(highS, curve)

	// The original value should not be mutated
	if highS.Cmp(original) != 0 {
		t.Errorf("normalizeLowS mutated the input: got %s, want %s", highS, original)
	}
}
