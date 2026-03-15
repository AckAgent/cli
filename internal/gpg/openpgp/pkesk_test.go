package openpgp

import (
	"bytes"
	"testing"
)

func TestParsePKESK_TooShort(t *testing.T) {
	_, err := ParsePKESK([]byte{0x03, 0x00})
	if err == nil {
		t.Error("expected error for too-short PKESK")
	}
}

func TestParsePKESK_UnsupportedVersion(t *testing.T) {
	data := make([]byte, 11)
	data[0] = 4 // version 4, not supported
	_, err := ParsePKESK(data)
	if err == nil {
		t.Error("expected error for unsupported version")
	}
}

func TestParsePKESK_UnsupportedAlgo(t *testing.T) {
	data := make([]byte, 11)
	data[0] = PKESKVersion3
	data[9] = PubKeyAlgoECDSA // not ECDH
	_, err := ParsePKESK(data)
	if err == nil {
		t.Error("expected error for unsupported algorithm")
	}
}

func TestParsePKESK_ECDH_P256(t *testing.T) {
	// Build a valid ECDH PKESK with P-256 ephemeral (65 bytes)
	pw := NewPacketWriter()
	pw.WriteByte(PKESKVersion3)              // version
	pw.Write([]byte{1, 2, 3, 4, 5, 6, 7, 8}) // key ID
	pw.WriteByte(PubKeyAlgoECDH)             // algorithm

	// Ephemeral point MPI: 65 bytes = 520 bits
	ephemeral := make([]byte, 65)
	ephemeral[0] = 0x04
	for i := 1; i < 65; i++ {
		ephemeral[i] = byte(i)
	}
	pw.Write(EncodeMPIFromBytes(ephemeral))

	// Wrapped key: length byte + key data
	wrappedKey := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	pw.WriteByte(byte(len(wrappedKey)))
	pw.Write(wrappedKey)

	pkt, err := ParsePKESK(pw.Bytes())
	if err != nil {
		t.Fatalf("ParsePKESK error: %v", err)
	}

	if pkt.Version != PKESKVersion3 {
		t.Errorf("version = %d, want %d", pkt.Version, PKESKVersion3)
	}
	if !bytes.Equal(pkt.KeyID, []byte{1, 2, 3, 4, 5, 6, 7, 8}) {
		t.Errorf("keyID = %x, want 0102030405060708", pkt.KeyID)
	}
	if pkt.Algorithm != PubKeyAlgoECDH {
		t.Errorf("algorithm = %d, want %d", pkt.Algorithm, PubKeyAlgoECDH)
	}
	if len(pkt.EphemeralPoint) != 65 {
		t.Errorf("ephemeral point length = %d, want 65", len(pkt.EphemeralPoint))
	}
	if !bytes.Equal(pkt.WrappedKey, wrappedKey) {
		t.Errorf("wrapped key = %x, want %x", pkt.WrappedKey, wrappedKey)
	}
}

func TestParsePKESK_ECDH_Curve25519(t *testing.T) {
	pw := NewPacketWriter()
	pw.WriteByte(PKESKVersion3)
	pw.Write(make([]byte, 8)) // key ID
	pw.WriteByte(PubKeyAlgoECDH)

	// Curve25519 ephemeral: 33 bytes with 0x40 prefix
	ephemeral := make([]byte, 33)
	ephemeral[0] = 0x40
	for i := 1; i < 33; i++ {
		ephemeral[i] = byte(i)
	}
	pw.Write(EncodeMPIFromBytes(ephemeral))

	wrappedKey := []byte{0x11, 0x22}
	pw.WriteByte(byte(len(wrappedKey)))
	pw.Write(wrappedKey)

	pkt, err := ParsePKESK(pw.Bytes())
	if err != nil {
		t.Fatalf("ParsePKESK Curve25519 error: %v", err)
	}
	if len(pkt.EphemeralPoint) != 33 {
		t.Errorf("ephemeral point length = %d, want 33", len(pkt.EphemeralPoint))
	}
}

func TestParsePKESK_BadEphemeralPrefix(t *testing.T) {
	pw := NewPacketWriter()
	pw.WriteByte(PKESKVersion3)
	pw.Write(make([]byte, 8))
	pw.WriteByte(PubKeyAlgoECDH)

	// 65 bytes but wrong prefix
	ephemeral := make([]byte, 65)
	ephemeral[0] = 0x02 // not 0x04
	pw.Write(EncodeMPIFromBytes(ephemeral))
	pw.WriteByte(0)

	_, err := ParsePKESK(pw.Bytes())
	if err == nil {
		t.Error("expected error for bad P-256 prefix")
	}
}

func TestParsePKESK_BadCurve25519Prefix(t *testing.T) {
	pw := NewPacketWriter()
	pw.WriteByte(PKESKVersion3)
	pw.Write(make([]byte, 8))
	pw.WriteByte(PubKeyAlgoECDH)

	// 33 bytes but wrong prefix
	ephemeral := make([]byte, 33)
	ephemeral[0] = 0x02 // not 0x40
	pw.Write(EncodeMPIFromBytes(ephemeral))
	pw.WriteByte(0)

	_, err := ParsePKESK(pw.Bytes())
	if err == nil {
		t.Error("expected error for bad Curve25519 prefix")
	}
}

func TestParsePKESK_BadEphemeralLength(t *testing.T) {
	pw := NewPacketWriter()
	pw.WriteByte(PKESKVersion3)
	pw.Write(make([]byte, 8))
	pw.WriteByte(PubKeyAlgoECDH)

	// 10 bytes - neither 65 nor 33
	ephemeral := make([]byte, 10)
	pw.Write(EncodeMPIFromBytes(ephemeral))
	pw.WriteByte(0)

	_, err := ParsePKESK(pw.Bytes())
	if err == nil {
		t.Error("expected error for wrong ephemeral point length")
	}
}

func TestParsePKESK_MissingWrappedKeyLength(t *testing.T) {
	pw := NewPacketWriter()
	pw.WriteByte(PKESKVersion3)
	pw.Write(make([]byte, 8))
	pw.WriteByte(PubKeyAlgoECDH)

	ephemeral := make([]byte, 65)
	ephemeral[0] = 0x04
	pw.Write(EncodeMPIFromBytes(ephemeral))
	// No wrapped key length byte

	_, err := ParsePKESK(pw.Bytes())
	if err == nil {
		t.Error("expected error for missing wrapped key length")
	}
}

func TestParsePKESK_WrappedKeyTruncated(t *testing.T) {
	pw := NewPacketWriter()
	pw.WriteByte(PKESKVersion3)
	pw.Write(make([]byte, 8))
	pw.WriteByte(PubKeyAlgoECDH)

	ephemeral := make([]byte, 65)
	ephemeral[0] = 0x04
	pw.Write(EncodeMPIFromBytes(ephemeral))
	pw.WriteByte(10) // claims 10 bytes of wrapped key but provides none

	_, err := ParsePKESK(pw.Bytes())
	if err == nil {
		t.Error("expected error for truncated wrapped key")
	}
}

func TestParsePKESK_ECDHDataTooShort(t *testing.T) {
	data := make([]byte, 11) // header + 1 byte after algo
	data[0] = PKESKVersion3
	data[9] = PubKeyAlgoECDH
	// Only 1 byte of ECDH data, too short for MPI

	_, err := ParsePKESK(data)
	if err == nil {
		t.Error("expected error for ECDH data too short")
	}
}

func TestReadMPI_TooShort(t *testing.T) {
	_, _, err := readMPI([]byte{0x00})
	if err == nil {
		t.Error("expected error for single byte MPI")
	}
}

func TestReadMPI_DataTruncated(t *testing.T) {
	// Claims 16 bits = 2 bytes, but only 1 byte available
	_, _, err := readMPI([]byte{0x00, 0x10, 0xAA})
	if err == nil {
		t.Error("expected error for truncated MPI data")
	}
}

func TestReadMPI_Valid(t *testing.T) {
	// 8 bits = 1 byte
	consumed, data, err := readMPI([]byte{0x00, 0x08, 0xFF})
	if err != nil {
		t.Fatalf("readMPI error: %v", err)
	}
	if consumed != 3 {
		t.Errorf("consumed = %d, want 3", consumed)
	}
	if !bytes.Equal(data, []byte{0xFF}) {
		t.Errorf("data = %x, want ff", data)
	}
}

func TestPKESKPacket_KeyIDString(t *testing.T) {
	pkt := &PKESKPacket{
		KeyID: []byte{0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44},
	}
	got := pkt.KeyIDString()
	if got != "AABBCCDD11223344" {
		t.Errorf("KeyIDString() = %q, want %q", got, "AABBCCDD11223344")
	}
}

func TestPKESKPacket_MatchesKeyID(t *testing.T) {
	keyID := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	pkt := &PKESKPacket{KeyID: keyID}

	// V4 fingerprint is 20 bytes, key ID is last 8
	fp := make([]byte, 20)
	copy(fp[12:], keyID)

	if !pkt.MatchesKeyID(fp) {
		t.Error("MatchesKeyID should return true for matching fingerprint")
	}

	// Different fingerprint
	fp2 := make([]byte, 20)
	if pkt.MatchesKeyID(fp2) {
		t.Error("MatchesKeyID should return false for different fingerprint")
	}

	// Short fingerprint
	if pkt.MatchesKeyID([]byte{0x01, 0x02}) {
		t.Error("MatchesKeyID should return false for short fingerprint")
	}
}

func TestPKESKPacket_IsWildcardKeyID(t *testing.T) {
	wildcard := &PKESKPacket{KeyID: make([]byte, 8)}
	if !wildcard.IsWildcardKeyID() {
		t.Error("all-zero key ID should be wildcard")
	}

	nonWildcard := &PKESKPacket{KeyID: []byte{0, 0, 0, 0, 0, 0, 0, 1}}
	if nonWildcard.IsWildcardKeyID() {
		t.Error("non-zero key ID should not be wildcard")
	}
}

func TestBuildPKESK_P256(t *testing.T) {
	keyID := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	ephemeral := make([]byte, 65)
	ephemeral[0] = 0x04
	wrappedKey := []byte{0xAA, 0xBB, 0xCC}

	body, err := BuildPKESK(keyID, ephemeral, wrappedKey)
	if err != nil {
		t.Fatalf("BuildPKESK error: %v", err)
	}

	// Should be parseable
	pkt, err := ParsePKESK(body)
	if err != nil {
		t.Fatalf("ParsePKESK roundtrip error: %v", err)
	}
	if !bytes.Equal(pkt.KeyID, keyID) {
		t.Errorf("roundtrip key ID mismatch")
	}
	if !bytes.Equal(pkt.WrappedKey, wrappedKey) {
		t.Errorf("roundtrip wrapped key mismatch")
	}
}

func TestBuildPKESK_Curve25519(t *testing.T) {
	keyID := make([]byte, 8)
	ephemeral := make([]byte, 33)
	ephemeral[0] = 0x40
	wrappedKey := []byte{0x11}

	body, err := BuildPKESK(keyID, ephemeral, wrappedKey)
	if err != nil {
		t.Fatalf("BuildPKESK Curve25519 error: %v", err)
	}

	pkt, err := ParsePKESK(body)
	if err != nil {
		t.Fatalf("ParsePKESK Curve25519 roundtrip error: %v", err)
	}
	if len(pkt.EphemeralPoint) != 33 {
		t.Errorf("ephemeral point length = %d, want 33", len(pkt.EphemeralPoint))
	}
}

func TestBuildPKESK_BadKeyIDLen(t *testing.T) {
	_, err := BuildPKESK([]byte{1, 2, 3}, make([]byte, 65), nil)
	if err == nil {
		t.Error("expected error for bad key ID length")
	}
}

func TestBuildPKESK_BadEphemeralLen(t *testing.T) {
	_, err := BuildPKESK(make([]byte, 8), make([]byte, 10), nil)
	if err == nil {
		t.Error("expected error for bad ephemeral point length")
	}
}
