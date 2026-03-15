package openpgp

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"
	"time"
)

func TestDecodeMPI(t *testing.T) {
	// Round-trip test: encode then decode
	original := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
	encoded := EncodeMPIFromBytes(original)

	decoded, consumed, err := DecodeMPI(encoded, 0)
	if err != nil {
		t.Fatalf("DecodeMPI failed: %v", err)
	}
	if consumed != len(encoded) {
		t.Errorf("consumed %d bytes, expected %d", consumed, len(encoded))
	}
	if len(decoded) != len(original) {
		t.Fatalf("decoded length %d, expected %d", len(decoded), len(original))
	}
	for i := range original {
		if decoded[i] != original[i] {
			t.Errorf("byte %d: got %02X, expected %02X", i, decoded[i], original[i])
		}
	}
}

func TestDecodeMPIWithLeadingZeros(t *testing.T) {
	// EncodeMPIFromBytes strips leading zeros, so decoded should too
	original := []byte{0x00, 0x00, 0x7F, 0xAB}
	encoded := EncodeMPIFromBytes(original)

	decoded, _, err := DecodeMPI(encoded, 0)
	if err != nil {
		t.Fatalf("DecodeMPI failed: %v", err)
	}
	// Should be [0x7F, 0xAB] after stripping leading zeros
	expected := []byte{0x7F, 0xAB}
	if len(decoded) != len(expected) {
		t.Fatalf("decoded length %d, expected %d", len(decoded), len(expected))
	}
	for i := range expected {
		if decoded[i] != expected[i] {
			t.Errorf("byte %d: got %02X, expected %02X", i, decoded[i], expected[i])
		}
	}
}

func TestDecodeMPIAtOffset(t *testing.T) {
	// Put some prefix bytes before the MPI
	prefix := []byte{0xFF, 0xFE, 0xFD}
	mpiData := EncodeMPIFromBytes([]byte{0x42})
	data := append(prefix, mpiData...)

	decoded, consumed, err := DecodeMPI(data, len(prefix))
	if err != nil {
		t.Fatalf("DecodeMPI at offset failed: %v", err)
	}
	if consumed != len(mpiData) {
		t.Errorf("consumed %d bytes, expected %d", consumed, len(mpiData))
	}
	if len(decoded) != 1 || decoded[0] != 0x42 {
		t.Errorf("decoded %v, expected [0x42]", decoded)
	}
}

func TestDecodeMPIErrors(t *testing.T) {
	// Too short for header
	_, _, err := DecodeMPI([]byte{0x00}, 0)
	if err == nil {
		t.Error("expected error for truncated header")
	}

	// Header says 16 bits (2 bytes) but only 1 byte available
	_, _, err = DecodeMPI([]byte{0x00, 0x10, 0xFF}, 0)
	if err == nil {
		t.Error("expected error for truncated body")
	}

	// Offset beyond data
	_, _, err = DecodeMPI([]byte{0x00, 0x01, 0xFF}, 5)
	if err == nil {
		t.Error("expected error for offset beyond data")
	}
}

func TestParseSignaturePacket(t *testing.T) {
	// Build a signature using SignatureBuilder and parse it back
	creationTime := time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC)
	fp := make([]byte, 20)
	for i := range fp {
		fp[i] = byte(i + 1)
	}
	keyID := KeyIDFromFingerprint(fp)

	sb := NewSignatureBuilder()
	sb.SetSignatureType(SigTypeBinary)
	sb.SetPubKeyAlgo(PubKeyAlgoECDSA)
	sb.SetCreationTime(creationTime)
	sb.SetIssuerFingerprint(fp)
	sb.SetIssuerKeyID(keyID)

	testData := []byte("test data for signature parsing")
	digest, header := sb.BuildHashInput(testData)

	// Create a fake 64-byte signature (r||s)
	fakeSig := make([]byte, 64)
	for i := range fakeSig {
		fakeSig[i] = byte(i)
	}

	sigPacket, err := sb.FinalizeSignature(header, digest, fakeSig)
	if err != nil {
		t.Fatalf("FinalizeSignature failed: %v", err)
	}

	// Parse the packet to get the body
	packets, err := ParseAllPackets(sigPacket)
	if err != nil {
		t.Fatalf("ParseAllPackets failed: %v", err)
	}
	if len(packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(packets))
	}
	if packets[0].Tag != PacketTagSignature {
		t.Fatalf("expected tag %d, got %d", PacketTagSignature, packets[0].Tag)
	}

	parsed, err := ParseSignaturePacket(packets[0].Body)
	if err != nil {
		t.Fatalf("ParseSignaturePacket failed: %v", err)
	}

	if parsed.Version != SigVersion4 {
		t.Errorf("version: got %d, expected %d", parsed.Version, SigVersion4)
	}
	if parsed.SigType != SigTypeBinary {
		t.Errorf("sigType: got %d, expected %d", parsed.SigType, SigTypeBinary)
	}
	if parsed.PubKeyAlgo != PubKeyAlgoECDSA {
		t.Errorf("pubKeyAlgo: got %d, expected %d", parsed.PubKeyAlgo, PubKeyAlgoECDSA)
	}
	if parsed.HashAlgo != HashAlgoSHA256 {
		t.Errorf("hashAlgo: got %d, expected %d", parsed.HashAlgo, HashAlgoSHA256)
	}
	if parsed.HashPrefix[0] != digest[0] || parsed.HashPrefix[1] != digest[1] {
		t.Errorf("hashPrefix: got %02X%02X, expected %02X%02X",
			parsed.HashPrefix[0], parsed.HashPrefix[1], digest[0], digest[1])
	}
	if parsed.CreationTime != uint32(creationTime.Unix()) {
		t.Errorf("creationTime: got %d, expected %d", parsed.CreationTime, creationTime.Unix())
	}
	if parsed.IssuerFP == nil {
		t.Fatal("issuerFP is nil")
	}
	for i := range fp {
		if parsed.IssuerFP[i] != fp[i] {
			t.Errorf("issuerFP byte %d: got %02X, expected %02X", i, parsed.IssuerFP[i], fp[i])
		}
	}
}

func TestVerifyDetachedECDSA(t *testing.T) {
	// Generate a real P-256 keypair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Marshal public key to uncompressed form
	pubKeyBytes := elliptic.Marshal(elliptic.P256(), privKey.PublicKey.X, privKey.PublicKey.Y)

	creationTime := time.Now()
	fp := V4Fingerprint(pubKeyBytes, creationTime)
	keyID := KeyIDFromFingerprint(fp)

	testData := []byte("Hello, this is test data for ECDSA verification")

	// Build signature using SignatureBuilder to get the digest
	sb := NewSignatureBuilder()
	sb.SetSignatureType(SigTypeBinary)
	sb.SetPubKeyAlgo(PubKeyAlgoECDSA)
	sb.SetCreationTime(creationTime)
	sb.SetIssuerFingerprint(fp)
	sb.SetIssuerKeyID(keyID)

	digest, header := sb.BuildHashInput(testData)

	// Sign the digest with the real key
	r, s, err := ecdsa.Sign(rand.Reader, privKey, digest)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	// Pad r and s to 32 bytes each
	rBytes := padTo32(r.Bytes())
	sBytes := padTo32(s.Bytes())
	rawSig := append(rBytes, sBytes...)

	sigPacket, err := sb.FinalizeSignature(header, digest, rawSig)
	if err != nil {
		t.Fatalf("FinalizeSignature failed: %v", err)
	}

	// Parse and verify
	packets, err := ParseAllPackets(sigPacket)
	if err != nil {
		t.Fatalf("ParseAllPackets failed: %v", err)
	}

	parsed, err := ParseSignaturePacket(packets[0].Body)
	if err != nil {
		t.Fatalf("ParseSignaturePacket failed: %v", err)
	}

	err = VerifyDetached(pubKeyBytes, false, testData, parsed)
	if err != nil {
		t.Fatalf("VerifyDetached failed: %v", err)
	}
}

func TestVerifyDetachedEd25519(t *testing.T) {
	// Generate a real Ed25519 keypair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	pubKeyBytes := []byte(pubKey)
	creationTime := time.Now()
	fp := V4FingerprintEd25519(pubKeyBytes, creationTime)
	keyID := KeyIDFromFingerprint(fp)

	testData := []byte("Hello, this is test data for Ed25519 verification")

	// Build signature
	sb := NewSignatureBuilder()
	sb.SetSignatureType(SigTypeBinary)
	sb.SetPubKeyAlgo(PubKeyAlgoEdDSA)
	sb.SetCreationTime(creationTime)
	sb.SetIssuerFingerprint(fp)
	sb.SetIssuerKeyID(keyID)

	digest, header := sb.BuildHashInput(testData)

	// Ed25519 in OpenPGP signs the digest
	edSig := ed25519.Sign(privKey, digest)

	sigPacket, err := sb.FinalizeSignature(header, digest, edSig)
	if err != nil {
		t.Fatalf("FinalizeSignature failed: %v", err)
	}

	// Parse and verify
	packets, err := ParseAllPackets(sigPacket)
	if err != nil {
		t.Fatalf("ParseAllPackets failed: %v", err)
	}

	parsed, err := ParseSignaturePacket(packets[0].Body)
	if err != nil {
		t.Fatalf("ParseSignaturePacket failed: %v", err)
	}

	err = VerifyDetached(pubKeyBytes, true, testData, parsed)
	if err != nil {
		t.Fatalf("VerifyDetached failed: %v", err)
	}
}

func TestVerifyBadSignatureECDSA(t *testing.T) {
	// Generate a real P-256 keypair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	pubKeyBytes := elliptic.Marshal(elliptic.P256(), privKey.PublicKey.X, privKey.PublicKey.Y)

	creationTime := time.Now()
	fp := V4Fingerprint(pubKeyBytes, creationTime)
	keyID := KeyIDFromFingerprint(fp)

	testData := []byte("original data")

	sb := NewSignatureBuilder()
	sb.SetSignatureType(SigTypeBinary)
	sb.SetPubKeyAlgo(PubKeyAlgoECDSA)
	sb.SetCreationTime(creationTime)
	sb.SetIssuerFingerprint(fp)
	sb.SetIssuerKeyID(keyID)

	digest, header := sb.BuildHashInput(testData)

	r, s, err := ecdsa.Sign(rand.Reader, privKey, digest)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	rBytes := padTo32(r.Bytes())
	sBytes := padTo32(s.Bytes())
	rawSig := append(rBytes, sBytes...)

	sigPacket, err := sb.FinalizeSignature(header, digest, rawSig)
	if err != nil {
		t.Fatalf("FinalizeSignature failed: %v", err)
	}

	packets, err := ParseAllPackets(sigPacket)
	if err != nil {
		t.Fatalf("ParseAllPackets failed: %v", err)
	}

	parsed, err := ParseSignaturePacket(packets[0].Body)
	if err != nil {
		t.Fatalf("ParseSignaturePacket failed: %v", err)
	}

	// Tamper: verify against different data
	tamperedData := []byte("tampered data")
	err = VerifyDetached(pubKeyBytes, false, tamperedData, parsed)
	if err == nil {
		t.Fatal("expected verification to fail with tampered data")
	}
}

func TestVerifyBadSignatureEd25519(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	pubKeyBytes := []byte(pubKey)
	creationTime := time.Now()
	fp := V4FingerprintEd25519(pubKeyBytes, creationTime)
	keyID := KeyIDFromFingerprint(fp)

	testData := []byte("original data")

	sb := NewSignatureBuilder()
	sb.SetSignatureType(SigTypeBinary)
	sb.SetPubKeyAlgo(PubKeyAlgoEdDSA)
	sb.SetCreationTime(creationTime)
	sb.SetIssuerFingerprint(fp)
	sb.SetIssuerKeyID(keyID)

	digest, header := sb.BuildHashInput(testData)
	edSig := ed25519.Sign(privKey, digest)

	sigPacket, err := sb.FinalizeSignature(header, digest, edSig)
	if err != nil {
		t.Fatalf("FinalizeSignature failed: %v", err)
	}

	packets, err := ParseAllPackets(sigPacket)
	if err != nil {
		t.Fatalf("ParseAllPackets failed: %v", err)
	}

	parsed, err := ParseSignaturePacket(packets[0].Body)
	if err != nil {
		t.Fatalf("ParseSignaturePacket failed: %v", err)
	}

	// Tamper: verify against different data
	tamperedData := []byte("tampered data")
	err = VerifyDetached(pubKeyBytes, true, tamperedData, parsed)
	if err == nil {
		t.Fatal("expected verification to fail with tampered data")
	}
}

func TestVerifyWrongKey(t *testing.T) {
	// Sign with one key, verify with another
	privKey1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key1: %v", err)
	}
	privKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key2: %v", err)
	}

	pubKey1Bytes := elliptic.Marshal(elliptic.P256(), privKey1.PublicKey.X, privKey1.PublicKey.Y)
	pubKey2Bytes := elliptic.Marshal(elliptic.P256(), privKey2.PublicKey.X, privKey2.PublicKey.Y)

	creationTime := time.Now()
	fp := V4Fingerprint(pubKey1Bytes, creationTime)
	keyID := KeyIDFromFingerprint(fp)

	testData := []byte("test data")

	sb := NewSignatureBuilder()
	sb.SetSignatureType(SigTypeBinary)
	sb.SetPubKeyAlgo(PubKeyAlgoECDSA)
	sb.SetCreationTime(creationTime)
	sb.SetIssuerFingerprint(fp)
	sb.SetIssuerKeyID(keyID)

	digest, header := sb.BuildHashInput(testData)

	// Sign with key1
	r, s, err := ecdsa.Sign(rand.Reader, privKey1, digest)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	rawSig := append(padTo32(r.Bytes()), padTo32(s.Bytes())...)

	sigPacket, err := sb.FinalizeSignature(header, digest, rawSig)
	if err != nil {
		t.Fatalf("FinalizeSignature failed: %v", err)
	}

	packets, err := ParseAllPackets(sigPacket)
	if err != nil {
		t.Fatalf("ParseAllPackets failed: %v", err)
	}

	parsed, err := ParseSignaturePacket(packets[0].Body)
	if err != nil {
		t.Fatalf("ParseSignaturePacket failed: %v", err)
	}

	// Verify with key2 — should fail
	err = VerifyDetached(pubKey2Bytes, false, testData, parsed)
	if err == nil {
		t.Fatal("expected verification to fail with wrong key")
	}
}

// padTo32 pads a byte slice to 32 bytes with leading zeros.
func padTo32(b []byte) []byte {
	if len(b) >= 32 {
		return b[:32]
	}
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return padded
}

// TestParseSubpacketArea tests subpacket parsing directly.
func TestParseSubpacketArea(t *testing.T) {
	// Build subpackets using SubpacketBuilder
	sb := NewSubpacketBuilder()
	creationTime := time.Date(2025, 6, 15, 10, 30, 0, 0, time.UTC)
	sb.AddCreationTime(creationTime)

	fp := make([]byte, 20)
	for i := range fp {
		fp[i] = byte(0xA0 + i)
	}
	sb.AddIssuerFingerprint(fp)

	data := sb.Bytes()

	parsedFP, _, parsedTime, err := ParseSubpacketArea(data)
	if err != nil {
		t.Fatalf("ParseSubpacketArea failed: %v", err)
	}

	if parsedTime != uint32(creationTime.Unix()) {
		t.Errorf("creationTime: got %d, expected %d", parsedTime, creationTime.Unix())
	}

	if parsedFP == nil {
		t.Fatal("issuerFP is nil")
	}
	for i := range fp {
		if parsedFP[i] != fp[i] {
			t.Errorf("issuerFP byte %d: got %02X, expected %02X", i, parsedFP[i], fp[i])
		}
	}
}

// TestVerifyArmoredSignature tests the full flow: create armored sig, dearmor, parse, verify.
func TestVerifyArmoredSignature(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	pubKeyBytes := elliptic.Marshal(elliptic.P256(), privKey.PublicKey.X, privKey.PublicKey.Y)
	creationTime := time.Now()
	fp := V4Fingerprint(pubKeyBytes, creationTime)
	keyID := KeyIDFromFingerprint(fp)

	testData := []byte("test data for armored signature verification")

	sb := NewSignatureBuilder()
	sb.SetSignatureType(SigTypeBinary)
	sb.SetPubKeyAlgo(PubKeyAlgoECDSA)
	sb.SetCreationTime(creationTime)
	sb.SetIssuerFingerprint(fp)
	sb.SetIssuerKeyID(keyID)

	digest, header := sb.BuildHashInput(testData)

	r, s, err := ecdsa.Sign(rand.Reader, privKey, digest)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	rawSig := append(padTo32(r.Bytes()), padTo32(s.Bytes())...)

	sigPacket, err := sb.FinalizeSignature(header, digest, rawSig)
	if err != nil {
		t.Fatalf("FinalizeSignature failed: %v", err)
	}

	// Armor the signature
	armored := ArmorSig(sigPacket)

	// Dearmor
	binary, armorType, err := Dearmor([]byte(armored))
	if err != nil {
		t.Fatalf("Dearmor failed: %v", err)
	}
	if armorType != "PGP SIGNATURE" {
		t.Errorf("armor type: got %q, expected %q", armorType, "PGP SIGNATURE")
	}

	// Parse and verify
	packets, err := ParseAllPackets(binary)
	if err != nil {
		t.Fatalf("ParseAllPackets failed: %v", err)
	}

	parsed, err := ParseSignaturePacket(packets[0].Body)
	if err != nil {
		t.Fatalf("ParseSignaturePacket failed: %v", err)
	}

	err = VerifyDetached(pubKeyBytes, false, testData, parsed)
	if err != nil {
		t.Fatalf("VerifyDetached failed: %v", err)
	}
}

// TestVerifyDetachedCompressedKey tests verification with a compressed P-256 key.
func TestVerifyDetachedCompressedKey(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Get compressed key
	compressedKey := elliptic.MarshalCompressed(elliptic.P256(), privKey.PublicKey.X, privKey.PublicKey.Y)
	// Get uncompressed key for signing
	uncompressedKey := elliptic.Marshal(elliptic.P256(), privKey.PublicKey.X, privKey.PublicKey.Y)

	creationTime := time.Now()
	fp := V4Fingerprint(uncompressedKey, creationTime)
	keyID := KeyIDFromFingerprint(fp)

	testData := []byte("test with compressed key")

	sb := NewSignatureBuilder()
	sb.SetSignatureType(SigTypeBinary)
	sb.SetPubKeyAlgo(PubKeyAlgoECDSA)
	sb.SetCreationTime(creationTime)
	sb.SetIssuerFingerprint(fp)
	sb.SetIssuerKeyID(keyID)

	digest, header := sb.BuildHashInput(testData)

	sigR, sigS, err := ecdsa.Sign(rand.Reader, privKey, digest)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	rawSig := append(padTo32(sigR.Bytes()), padTo32(sigS.Bytes())...)

	sigPacket, err := sb.FinalizeSignature(header, digest, rawSig)
	if err != nil {
		t.Fatalf("FinalizeSignature failed: %v", err)
	}

	packets, err := ParseAllPackets(sigPacket)
	if err != nil {
		t.Fatalf("ParseAllPackets failed: %v", err)
	}

	parsed, err := ParseSignaturePacket(packets[0].Body)
	if err != nil {
		t.Fatalf("ParseSignaturePacket failed: %v", err)
	}

	// Verify with compressed key — should decompress internally
	err = VerifyDetached(compressedKey, false, testData, parsed)
	if err != nil {
		t.Fatalf("VerifyDetached with compressed key failed: %v", err)
	}
}

// Ensure big is used (test helper needs it indirectly via ecdsa)
var _ = new(big.Int)
