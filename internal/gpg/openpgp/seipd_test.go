package openpgp

import (
	"bytes"
	"testing"
)

func TestChunkSize_V2(t *testing.T) {
	pkt := &SEIPDPacket{Version: SEIPDVersion2, ChunkSizeByte: 0}
	// 2^(0+6) = 64
	if got := pkt.ChunkSize(); got != 64 {
		t.Errorf("ChunkSize() with byte 0 = %d, want 64", got)
	}

	pkt.ChunkSizeByte = 4
	// 2^(4+6) = 1024
	if got := pkt.ChunkSize(); got != 1024 {
		t.Errorf("ChunkSize() with byte 4 = %d, want 1024", got)
	}
}

func TestChunkSize_V1_ReturnsZero(t *testing.T) {
	pkt := &SEIPDPacket{Version: SEIPDVersion1, ChunkSizeByte: 4}
	if got := pkt.ChunkSize(); got != 0 {
		t.Errorf("ChunkSize() for v1 = %d, want 0", got)
	}
}

func TestParseSEIPD_Empty(t *testing.T) {
	_, err := ParseSEIPD(nil)
	if err == nil {
		t.Error("expected error for empty SEIPD")
	}
}

func TestParseSEIPD_UnsupportedVersion(t *testing.T) {
	_, err := ParseSEIPD([]byte{5}) // version 5
	if err == nil {
		t.Error("expected error for unsupported version")
	}
}

func TestParseSEIPD_V1(t *testing.T) {
	ciphertext := []byte{0xAA, 0xBB, 0xCC}
	body := append([]byte{SEIPDVersion1}, ciphertext...)

	pkt, err := ParseSEIPD(body)
	if err != nil {
		t.Fatalf("ParseSEIPD v1 error: %v", err)
	}
	if pkt.Version != SEIPDVersion1 {
		t.Errorf("version = %d, want %d", pkt.Version, SEIPDVersion1)
	}
	if !bytes.Equal(pkt.Ciphertext, ciphertext) {
		t.Errorf("ciphertext = %x, want %x", pkt.Ciphertext, ciphertext)
	}
}

func TestParseSEIPD_V1_TooShort(t *testing.T) {
	_, err := ParseSEIPD([]byte{SEIPDVersion1})
	if err == nil {
		t.Error("expected error for v1 packet with no ciphertext")
	}
}

func TestParseSEIPD_V2(t *testing.T) {
	ciphertext := []byte{0xDD, 0xEE}
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i + 1)
	}

	body := make([]byte, 36+len(ciphertext))
	body[0] = SEIPDVersion2
	body[1] = SymAlgoAES256 // cipher
	body[2] = AEADAlgoGCM   // aead
	body[3] = 6             // chunk size byte
	copy(body[4:36], salt)
	copy(body[36:], ciphertext)

	pkt, err := ParseSEIPD(body)
	if err != nil {
		t.Fatalf("ParseSEIPD v2 error: %v", err)
	}
	if pkt.Version != SEIPDVersion2 {
		t.Errorf("version = %d, want %d", pkt.Version, SEIPDVersion2)
	}
	if pkt.CipherAlgo != SymAlgoAES256 {
		t.Errorf("cipher = %d, want %d", pkt.CipherAlgo, SymAlgoAES256)
	}
	if pkt.AEADAlgo != AEADAlgoGCM {
		t.Errorf("aead = %d, want %d", pkt.AEADAlgo, AEADAlgoGCM)
	}
	if pkt.ChunkSizeByte != 6 {
		t.Errorf("chunk size byte = %d, want 6", pkt.ChunkSizeByte)
	}
	if !bytes.Equal(pkt.Salt, salt) {
		t.Errorf("salt mismatch")
	}
	if !bytes.Equal(pkt.Ciphertext, ciphertext) {
		t.Errorf("ciphertext mismatch")
	}
}

func TestParseSEIPD_V2_TooShort(t *testing.T) {
	body := make([]byte, 10)
	body[0] = SEIPDVersion2
	_, err := ParseSEIPD(body)
	if err == nil {
		t.Error("expected error for too-short v2 SEIPD")
	}
}

func TestBuildSEIPDv1(t *testing.T) {
	ciphertext := []byte{0x01, 0x02, 0x03}
	body := BuildSEIPDv1(ciphertext)

	pkt, err := ParseSEIPD(body)
	if err != nil {
		t.Fatalf("roundtrip error: %v", err)
	}
	if pkt.Version != SEIPDVersion1 {
		t.Errorf("version = %d, want %d", pkt.Version, SEIPDVersion1)
	}
	if !bytes.Equal(pkt.Ciphertext, ciphertext) {
		t.Errorf("ciphertext mismatch")
	}
}

func TestBuildSEIPDv2(t *testing.T) {
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i)
	}
	ciphertext := []byte{0xAA, 0xBB}

	body, err := BuildSEIPDv2(SymAlgoAES128, AEADAlgoOCB, 3, salt, ciphertext)
	if err != nil {
		t.Fatalf("BuildSEIPDv2 error: %v", err)
	}

	pkt, err := ParseSEIPD(body)
	if err != nil {
		t.Fatalf("roundtrip error: %v", err)
	}
	if pkt.CipherAlgo != SymAlgoAES128 {
		t.Errorf("cipher = %d, want %d", pkt.CipherAlgo, SymAlgoAES128)
	}
	if pkt.AEADAlgo != AEADAlgoOCB {
		t.Errorf("aead = %d, want %d", pkt.AEADAlgo, AEADAlgoOCB)
	}
	if pkt.ChunkSizeByte != 3 {
		t.Errorf("chunk size byte = %d, want 3", pkt.ChunkSizeByte)
	}
}

func TestBuildSEIPDv2_BadSaltLen(t *testing.T) {
	_, err := BuildSEIPDv2(SymAlgoAES256, AEADAlgoGCM, 0, make([]byte, 16), nil)
	if err == nil {
		t.Error("expected error for wrong salt length")
	}
}

func TestParseEncryptedMessage_Valid(t *testing.T) {
	// Build a PKESK body
	keyID := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	ephemeral := make([]byte, 65)
	ephemeral[0] = 0x04
	wrappedKey := []byte{0xAA}

	pkeskBody, err := BuildPKESK(keyID, ephemeral, wrappedKey)
	if err != nil {
		t.Fatalf("BuildPKESK error: %v", err)
	}

	// Build a SEIPD body
	seipdBody := BuildSEIPDv1([]byte{0x01, 0x02, 0x03})

	// Build packets
	pkeskPacket := BuildPacket(PacketTagPKESK, pkeskBody)
	seipdPacket := BuildPacket(PacketTagSEIPD, seipdBody)

	data := append(pkeskPacket, seipdPacket...)

	msg, err := ParseEncryptedMessage(data)
	if err != nil {
		t.Fatalf("ParseEncryptedMessage error: %v", err)
	}
	if len(msg.PKESKPackets) != 1 {
		t.Errorf("PKESK count = %d, want 1", len(msg.PKESKPackets))
	}
	if msg.SEIPDPacket == nil {
		t.Error("SEIPD packet should not be nil")
	}
}

func TestParseEncryptedMessage_NoPKESK(t *testing.T) {
	seipdBody := BuildSEIPDv1([]byte{0x01})
	data := BuildPacket(PacketTagSEIPD, seipdBody)

	_, err := ParseEncryptedMessage(data)
	if err == nil {
		t.Error("expected error for missing PKESK")
	}
}

func TestParseEncryptedMessage_NoSEIPD(t *testing.T) {
	keyID := make([]byte, 8)
	ephemeral := make([]byte, 65)
	ephemeral[0] = 0x04
	pkeskBody, _ := BuildPKESK(keyID, ephemeral, []byte{0xAA})
	data := BuildPacket(PacketTagPKESK, pkeskBody)

	_, err := ParseEncryptedMessage(data)
	if err == nil {
		t.Error("expected error for missing SEIPD")
	}
}

func TestParseEncryptedMessage_MultipleSEIPD(t *testing.T) {
	keyID := make([]byte, 8)
	ephemeral := make([]byte, 65)
	ephemeral[0] = 0x04
	pkeskBody, _ := BuildPKESK(keyID, ephemeral, []byte{0xAA})

	seipd1 := BuildSEIPDv1([]byte{0x01})
	seipd2 := BuildSEIPDv1([]byte{0x02})

	data := append(BuildPacket(PacketTagPKESK, pkeskBody), BuildPacket(PacketTagSEIPD, seipd1)...)
	data = append(data, BuildPacket(PacketTagSEIPD, seipd2)...)

	_, err := ParseEncryptedMessage(data)
	if err == nil {
		t.Error("expected error for multiple SEIPD packets")
	}
}

func TestParseEncryptedMessage_Empty(t *testing.T) {
	_, err := ParseEncryptedMessage(nil)
	if err == nil {
		t.Error("expected error for empty data")
	}
}

func TestFindMatchingPKESK_SpecificKeyID(t *testing.T) {
	keyID := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	fp := make([]byte, 20)
	copy(fp[12:], keyID)

	msg := &EncryptedMessage{
		PKESKPackets: []*PKESKPacket{
			{KeyID: keyID},
		},
	}

	pkesk, matchedFP := msg.FindMatchingPKESK([][]byte{fp})
	if pkesk == nil {
		t.Fatal("FindMatchingPKESK should find matching PKESK")
	}
	if !bytes.Equal(matchedFP, fp) {
		t.Error("matched fingerprint mismatch")
	}
}

func TestFindMatchingPKESK_WildcardKeyID(t *testing.T) {
	fp := make([]byte, 20)
	fp[19] = 0x01

	msg := &EncryptedMessage{
		PKESKPackets: []*PKESKPacket{
			{KeyID: make([]byte, 8)}, // all zeros = wildcard
		},
	}

	pkesk, matchedFP := msg.FindMatchingPKESK([][]byte{fp})
	if pkesk == nil {
		t.Fatal("FindMatchingPKESK should match wildcard")
	}
	if !bytes.Equal(matchedFP, fp) {
		t.Error("should match first fingerprint for wildcard")
	}
}

func TestFindMatchingPKESK_WildcardNoFingerprints(t *testing.T) {
	msg := &EncryptedMessage{
		PKESKPackets: []*PKESKPacket{
			{KeyID: make([]byte, 8)},
		},
	}

	pkesk, _ := msg.FindMatchingPKESK(nil)
	if pkesk != nil {
		t.Error("wildcard with no fingerprints should not match")
	}
}

func TestFindMatchingPKESK_NoMatch(t *testing.T) {
	msg := &EncryptedMessage{
		PKESKPackets: []*PKESKPacket{
			{KeyID: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}},
		},
	}

	fp := make([]byte, 20)
	pkesk, _ := msg.FindMatchingPKESK([][]byte{fp})
	if pkesk != nil {
		t.Error("should not match different fingerprint")
	}
}
