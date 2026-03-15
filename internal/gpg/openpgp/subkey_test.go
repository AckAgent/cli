package openpgp

import (
	"encoding/hex"
	"testing"
	"time"
)

func TestReverseBytes(t *testing.T) {
	tests := []struct {
		input []byte
		want  []byte
	}{
		{[]byte{1, 2, 3, 4}, []byte{4, 3, 2, 1}},
		{[]byte{0xFF}, []byte{0xFF}},
		{[]byte{}, []byte{}},
		{[]byte{0xAA, 0xBB}, []byte{0xBB, 0xAA}},
	}

	for _, tt := range tests {
		got := reverseBytes(tt.input)
		if hex.EncodeToString(got) != hex.EncodeToString(tt.want) {
			t.Errorf("reverseBytes(%x) = %x, want %x", tt.input, got, tt.want)
		}
	}
}

func TestV4FingerprintECDH(t *testing.T) {
	// Use a valid uncompressed P-256 public key (65 bytes, 0x04 prefix)
	pubKey := make([]byte, 65)
	pubKey[0] = 0x04
	for i := 1; i < 65; i++ {
		pubKey[i] = byte(i)
	}
	creationTime := time.Unix(1700000000, 0)

	fp := V4FingerprintECDH(pubKey, creationTime)
	if len(fp) != 20 {
		t.Errorf("ECDH fingerprint should be 20 bytes, got %d", len(fp))
	}

	// Should be deterministic
	fp2 := V4FingerprintECDH(pubKey, creationTime)
	if hex.EncodeToString(fp) != hex.EncodeToString(fp2) {
		t.Error("ECDH fingerprint should be deterministic")
	}

	// Different from ECDSA fingerprint (different algorithm byte)
	ecdsaFP := V4Fingerprint(pubKey, creationTime)
	if hex.EncodeToString(fp) == hex.EncodeToString(ecdsaFP) {
		t.Error("ECDH fingerprint should differ from ECDSA fingerprint")
	}
}

func TestV4FingerprintCurve25519ECDH(t *testing.T) {
	pubKey := make([]byte, 32)
	for i := range pubKey {
		pubKey[i] = byte(i + 50)
	}
	creationTime := time.Unix(1700000000, 0)

	fp := V4FingerprintCurve25519ECDH(pubKey, creationTime)
	if len(fp) != 20 {
		t.Errorf("Curve25519 ECDH fingerprint should be 20 bytes, got %d", len(fp))
	}

	// Should be deterministic
	fp2 := V4FingerprintCurve25519ECDH(pubKey, creationTime)
	if hex.EncodeToString(fp) != hex.EncodeToString(fp2) {
		t.Error("Curve25519 ECDH fingerprint should be deterministic")
	}
}

func TestBuildSubkeyPacket(t *testing.T) {
	pubKey := make([]byte, 65)
	pubKey[0] = 0x04
	creationTime := time.Unix(1700000000, 0)

	packet := BuildSubkeyPacket(pubKey, creationTime)
	if len(packet) == 0 {
		t.Fatal("BuildSubkeyPacket returned empty packet")
	}

	// Parse and verify tag
	reader := NewPacketReader(packet)
	parsed, err := reader.Next()
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}
	if parsed.Tag != PacketTagPublicSubkey {
		t.Errorf("tag = %d, want %d", parsed.Tag, PacketTagPublicSubkey)
	}
}

func TestBuildCurve25519SubkeyPacket(t *testing.T) {
	pubKey := make([]byte, 32)
	for i := range pubKey {
		pubKey[i] = byte(i)
	}
	creationTime := time.Unix(1700000000, 0)

	packet := BuildCurve25519SubkeyPacket(pubKey, creationTime)
	if len(packet) == 0 {
		t.Fatal("BuildCurve25519SubkeyPacket returned empty packet")
	}

	reader := NewPacketReader(packet)
	parsed, err := reader.Next()
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}
	if parsed.Tag != PacketTagPublicSubkey {
		t.Errorf("tag = %d, want %d", parsed.Tag, PacketTagPublicSubkey)
	}
}

func TestNewSubkeyBindingBuilder(t *testing.T) {
	fp := make([]byte, 20)
	subkeyPub := make([]byte, 65)
	subkeyPub[0] = 0x04

	builder := NewSubkeyBindingBuilder(fp, subkeyPub, time.Unix(1700000000, 0))
	if builder == nil {
		t.Fatal("NewSubkeyBindingBuilder returned nil")
	}
}

func TestSubkeyBindingBuilder_SetSignatureTime(t *testing.T) {
	fp := make([]byte, 20)
	subkeyPub := make([]byte, 65)
	subkeyPub[0] = 0x04

	builder := NewSubkeyBindingBuilder(fp, subkeyPub, time.Unix(1700000000, 0))
	sigTime := time.Unix(1700001000, 0)
	result := builder.SetSignatureTime(sigTime)

	if result != builder {
		t.Error("SetSignatureTime should return builder for chaining")
	}
}

func TestSubkeyBindingBuilder_BuildHashInput(t *testing.T) {
	fp := make([]byte, 20)
	for i := range fp {
		fp[i] = byte(i + 1)
	}
	subkeyPub := make([]byte, 65)
	subkeyPub[0] = 0x04

	builder := NewSubkeyBindingBuilder(fp, subkeyPub, time.Unix(1700000000, 0))
	builder.SetSignatureTime(time.Unix(1700001000, 0))

	digest, header := builder.BuildHashInput()
	if len(digest) != 32 { // SHA-256
		t.Errorf("digest length = %d, want 32", len(digest))
	}
	if len(header) == 0 {
		t.Error("header should not be empty")
	}

	// Header should start with version 4
	if header[0] != SigVersion4 {
		t.Errorf("header[0] = %d, want %d", header[0], SigVersion4)
	}
	// Followed by subkey binding type
	if header[1] != SignatureTypeSubkeyBinding {
		t.Errorf("header[1] = %d, want %d", header[1], SignatureTypeSubkeyBinding)
	}
}

func TestBuildSubkeyBindingSignature_ECDSA(t *testing.T) {
	primaryPub := make([]byte, 65)
	primaryPub[0] = 0x04
	primaryFP := make([]byte, 20)
	for i := range primaryFP {
		primaryFP[i] = byte(i + 1)
	}
	subkeyPub := make([]byte, 65)
	subkeyPub[0] = 0x04

	sigPacket, err := BuildSubkeyBindingSignature(
		primaryPub, primaryFP, time.Unix(1700000000, 0),
		PubKeyAlgoECDSA,
		subkeyPub, time.Unix(1700001000, 0),
		false, // P-256 ECDH
		func(digest []byte) ([]byte, error) {
			// Return a mock 64-byte signature (r || s)
			sig := make([]byte, 64)
			for i := range sig {
				sig[i] = byte(i + 1)
			}
			return sig, nil
		},
	)
	if err != nil {
		t.Fatalf("BuildSubkeyBindingSignature error: %v", err)
	}

	// Should be a valid packet
	reader := NewPacketReader(sigPacket)
	parsed, err := reader.Next()
	if err != nil {
		t.Fatalf("failed to parse signature packet: %v", err)
	}
	if parsed.Tag != PacketTagSignature {
		t.Errorf("tag = %d, want %d", parsed.Tag, PacketTagSignature)
	}
}

func TestBuildSubkeyBindingSignature_EdDSA(t *testing.T) {
	primaryPub := make([]byte, 32) // Ed25519 key
	primaryFP := make([]byte, 20)
	subkeyPub := make([]byte, 32) // Curve25519 subkey

	sigPacket, err := BuildSubkeyBindingSignature(
		primaryPub, primaryFP, time.Unix(1700000000, 0),
		PubKeyAlgoEdDSA,
		subkeyPub, time.Unix(1700001000, 0),
		true, // Curve25519 ECDH
		func(digest []byte) ([]byte, error) {
			// Return a mock 64-byte EdDSA signature
			return make([]byte, 64), nil
		},
	)
	if err != nil {
		t.Fatalf("BuildSubkeyBindingSignature (EdDSA) error: %v", err)
	}

	reader := NewPacketReader(sigPacket)
	parsed, err := reader.Next()
	if err != nil {
		t.Fatalf("failed to parse EdDSA signature packet: %v", err)
	}
	if parsed.Tag != PacketTagSignature {
		t.Errorf("tag = %d, want %d", parsed.Tag, PacketTagSignature)
	}
}
