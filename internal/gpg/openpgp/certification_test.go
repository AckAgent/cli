package openpgp

import (
	"bytes"
	"testing"
	"time"
)

func TestCertificationBuilder(t *testing.T) {
	// Test P-256 key (65 bytes: 0x04 || X || Y)
	pubKey := make([]byte, 65)
	pubKey[0] = 0x04
	for i := 1; i < len(pubKey); i++ {
		pubKey[i] = byte(i)
	}
	creationTime := time.Unix(1700000000, 0)
	userID := "Test User <test@example.com>"

	builder := NewCertificationBuilder(pubKey, creationTime, userID)
	builder.SetSignatureTime(creationTime)

	digest, header, hashedData, unhashedData := builder.BuildHashInput()

	// Digest should be 32 bytes (SHA-256)
	if len(digest) != 32 {
		t.Errorf("digest length = %d, want 32", len(digest))
	}

	// Header should start with version 4 and type 0x13
	if len(header) < 2 {
		t.Fatal("header too short")
	}
	if header[0] != SigVersion4 {
		t.Errorf("header version = %d, want %d", header[0], SigVersion4)
	}
	if header[1] != SigTypePositiveCertification {
		t.Errorf("header sig type = 0x%02x, want 0x%02x", header[1], SigTypePositiveCertification)
	}

	// Should have hashed subpackets (at least creation time + key flags + issuer fingerprint)
	if len(hashedData) == 0 {
		t.Error("hashedData should not be empty")
	}

	// Should have unhashed subpackets (at least issuer key ID)
	if len(unhashedData) == 0 {
		t.Error("unhashedData should not be empty")
	}
}

func TestCertificationBuilder_Ed25519(t *testing.T) {
	// Test Ed25519 key (32 bytes)
	pubKey := make([]byte, 32)
	for i := range pubKey {
		pubKey[i] = byte(i)
	}
	creationTime := time.Unix(1700000000, 0)
	userID := "Ed25519 User <ed@example.com>"

	builder := NewCertificationBuilder(pubKey, creationTime, userID)

	// Should detect Ed25519 from key size
	if builder.pubKeyAlgo != PubKeyAlgoEdDSA {
		t.Errorf("pubKeyAlgo = %d, want %d (EdDSA)", builder.pubKeyAlgo, PubKeyAlgoEdDSA)
	}

	digest, header, _, _ := builder.BuildHashInput()

	// Digest should be 32 bytes
	if len(digest) != 32 {
		t.Errorf("digest length = %d, want 32", len(digest))
	}

	// Header should indicate EdDSA algorithm
	if header[2] != PubKeyAlgoEdDSA {
		t.Errorf("header algo = %d, want %d (EdDSA)", header[2], PubKeyAlgoEdDSA)
	}
}

func TestFinalizeCertificationSignature_ECDSA(t *testing.T) {
	pubKey := make([]byte, 65)
	pubKey[0] = 0x04
	for i := 1; i < len(pubKey); i++ {
		pubKey[i] = byte(i)
	}
	creationTime := time.Unix(1700000000, 0)
	userID := "Test User <test@example.com>"

	builder := NewCertificationBuilder(pubKey, creationTime, userID)
	digest, header, hashedData, unhashedData := builder.BuildHashInput()

	// Simulate a 64-byte ECDSA signature (r || s)
	rawSig := make([]byte, 64)
	for i := range rawSig {
		rawSig[i] = byte(i + 100)
	}

	sigPacket := FinalizeCertificationSignature(header, hashedData, unhashedData, digest, rawSig, PubKeyAlgoECDSA)

	// Should be a signature packet (tag 2)
	if len(sigPacket) == 0 {
		t.Fatal("signature packet is empty")
	}

	// Old format packet tag for signature: 0x88 (0x80 | (2 << 2) | 0)
	tag := sigPacket[0]
	packetTag := (tag & 0x3C) >> 2
	if packetTag != PacketTagSignature {
		t.Errorf("packet tag = %d, want %d", packetTag, PacketTagSignature)
	}

	// Verify hash prefix is included (first 2 bytes of digest)
	// Need to parse the packet to find the hash prefix location
	// For now, just verify the packet is non-empty and well-formed
	if len(sigPacket) < 20 {
		t.Errorf("signature packet too short: %d bytes", len(sigPacket))
	}
}

func TestFinalizeCertificationSignature_EdDSA(t *testing.T) {
	pubKey := make([]byte, 32) // Ed25519
	for i := range pubKey {
		pubKey[i] = byte(i)
	}
	creationTime := time.Unix(1700000000, 0)
	userID := "Ed25519 User <ed@example.com>"

	builder := NewCertificationBuilder(pubKey, creationTime, userID)
	digest, header, hashedData, unhashedData := builder.BuildHashInput()

	// Simulate a 64-byte Ed25519 signature
	rawSig := make([]byte, 64)
	for i := range rawSig {
		rawSig[i] = byte(i + 50)
	}

	sigPacket := FinalizeCertificationSignature(header, hashedData, unhashedData, digest, rawSig, PubKeyAlgoEdDSA)

	if len(sigPacket) == 0 {
		t.Fatal("signature packet is empty")
	}

	tag := sigPacket[0]
	packetTag := (tag & 0x3C) >> 2
	if packetTag != PacketTagSignature {
		t.Errorf("packet tag = %d, want %d", packetTag, PacketTagSignature)
	}
}

func TestBuildCertificationHashInput(t *testing.T) {
	pubKey := make([]byte, 65)
	pubKey[0] = 0x04
	for i := 1; i < len(pubKey); i++ {
		pubKey[i] = byte(i)
	}
	creationTime := time.Unix(1700000000, 0)
	signatureTime := time.Unix(1700000100, 0)
	userID := "Test User <test@example.com>"

	digest, header, hashedData, unhashedData, pubKeyAlgo := BuildCertificationHashInput(
		pubKey, creationTime, userID, signatureTime,
	)

	if len(digest) != 32 {
		t.Errorf("digest length = %d, want 32", len(digest))
	}
	if len(header) < 6 {
		t.Errorf("header length = %d, want >= 6", len(header))
	}
	if len(hashedData) == 0 {
		t.Error("hashedData should not be empty")
	}
	if len(unhashedData) == 0 {
		t.Error("unhashedData should not be empty")
	}
	if pubKeyAlgo != PubKeyAlgoECDSA {
		t.Errorf("pubKeyAlgo = %d, want %d", pubKeyAlgo, PubKeyAlgoECDSA)
	}
}

func TestBuildSubkeyBindingHashInput(t *testing.T) {
	primaryPubKey := make([]byte, 65)
	primaryPubKey[0] = 0x04
	subkeyPubKey := make([]byte, 65)
	subkeyPubKey[0] = 0x04
	for i := 1; i < 65; i++ {
		primaryPubKey[i] = byte(i)
		subkeyPubKey[i] = byte(i + 64)
	}
	creationTime := time.Unix(1700000000, 0)
	signatureTime := time.Unix(1700000100, 0)

	digest, header, hashedData, unhashedData := BuildSubkeyBindingHashInput(
		primaryPubKey, creationTime, subkeyPubKey, creationTime, signatureTime, PubKeyAlgoECDSA,
	)

	// Digest should be 32 bytes
	if len(digest) != 32 {
		t.Errorf("digest length = %d, want 32", len(digest))
	}

	// Header should have type 0x18 (subkey binding)
	if header[1] != SigTypeSubkeyBinding {
		t.Errorf("header sig type = 0x%02x, want 0x%02x", header[1], SigTypeSubkeyBinding)
	}

	if len(hashedData) == 0 {
		t.Error("hashedData should not be empty")
	}
	if len(unhashedData) == 0 {
		t.Error("unhashedData should not be empty")
	}
}

func TestFinalizeBindingSignature(t *testing.T) {
	primaryPubKey := make([]byte, 65)
	primaryPubKey[0] = 0x04
	subkeyPubKey := make([]byte, 65)
	subkeyPubKey[0] = 0x04
	for i := 1; i < 65; i++ {
		primaryPubKey[i] = byte(i)
		subkeyPubKey[i] = byte(i + 64)
	}
	creationTime := time.Unix(1700000000, 0)
	signatureTime := time.Unix(1700000100, 0)

	digest, header, hashedData, unhashedData := BuildSubkeyBindingHashInput(
		primaryPubKey, creationTime, subkeyPubKey, creationTime, signatureTime, PubKeyAlgoECDSA,
	)

	rawSig := make([]byte, 64)
	for i := range rawSig {
		rawSig[i] = byte(i + 200)
	}

	sigPacket := FinalizeBindingSignature(header, hashedData, unhashedData, digest, rawSig, PubKeyAlgoECDSA)

	if len(sigPacket) == 0 {
		t.Fatal("binding signature packet is empty")
	}

	tag := sigPacket[0]
	packetTag := (tag & 0x3C) >> 2
	if packetTag != PacketTagSignature {
		t.Errorf("packet tag = %d, want %d", packetTag, PacketTagSignature)
	}
}

func TestCertificationDigestConsistency(t *testing.T) {
	// Verify that the same inputs produce the same digest
	pubKey := make([]byte, 65)
	pubKey[0] = 0x04
	for i := 1; i < len(pubKey); i++ {
		pubKey[i] = byte(i)
	}
	creationTime := time.Unix(1700000000, 0)
	signatureTime := time.Unix(1700000100, 0)
	userID := "Consistency Test <test@example.com>"

	digest1, _, _, _, _ := BuildCertificationHashInput(pubKey, creationTime, userID, signatureTime)
	digest2, _, _, _, _ := BuildCertificationHashInput(pubKey, creationTime, userID, signatureTime)

	if !bytes.Equal(digest1, digest2) {
		t.Error("digests should be equal for same inputs")
	}
}

func TestCertificationDifferentInputsDifferentDigests(t *testing.T) {
	pubKey := make([]byte, 65)
	pubKey[0] = 0x04
	for i := 1; i < len(pubKey); i++ {
		pubKey[i] = byte(i)
	}
	creationTime := time.Unix(1700000000, 0)
	signatureTime := time.Unix(1700000100, 0)

	digest1, _, _, _, _ := BuildCertificationHashInput(pubKey, creationTime, "User One <one@example.com>", signatureTime)
	digest2, _, _, _, _ := BuildCertificationHashInput(pubKey, creationTime, "User Two <two@example.com>", signatureTime)

	if bytes.Equal(digest1, digest2) {
		t.Error("digests should differ for different user IDs")
	}
}

func TestKeyFlagsInCertification(t *testing.T) {
	pubKey := make([]byte, 65)
	pubKey[0] = 0x04
	for i := 1; i < len(pubKey); i++ {
		pubKey[i] = byte(i)
	}
	creationTime := time.Unix(1700000000, 0)
	userID := "Test User <test@example.com>"

	builder := NewCertificationBuilder(pubKey, creationTime, userID)

	// Default flags should be 0x03 (certify + sign)
	if builder.keyFlags != 0x03 {
		t.Errorf("default keyFlags = 0x%02x, want 0x03", builder.keyFlags)
	}

	// Set custom flags
	builder.SetKeyFlags(0x0F) // certify + sign + encrypt comm + encrypt storage
	if builder.keyFlags != 0x0F {
		t.Errorf("keyFlags after SetKeyFlags = 0x%02x, want 0x0F", builder.keyFlags)
	}
}
