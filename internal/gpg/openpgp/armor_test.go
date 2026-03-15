package openpgp

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestCRC24_Deterministic(t *testing.T) {
	// CRC24 should be deterministic
	data := []byte("Hello, OpenPGP!")
	crc1 := CRC24(data)
	crc2 := CRC24(data)
	if crc1 != crc2 {
		t.Error("CRC24 should be deterministic")
	}

	// Should be 24-bit (3 bytes)
	if crc1 > 0xFFFFFF {
		t.Errorf("CRC24 should be 24-bit, got 0x%X", crc1)
	}
}

func TestCRC24_EmptyData(t *testing.T) {
	crc := CRC24(nil)
	// Initial value masked to 24 bits should be returned after no iterations
	if crc > 0xFFFFFF {
		t.Errorf("CRC24 of empty data should be 24-bit, got 0x%X", crc)
	}
}

func TestEncodeCRC24_Format(t *testing.T) {
	data := []byte("test data")
	encoded := EncodeCRC24(data)
	if !strings.HasPrefix(encoded, "=") {
		t.Errorf("EncodeCRC24 should start with '=', got %q", encoded)
	}
	// Should be = + 4 base64 chars (3 bytes = 4 base64 chars)
	if len(encoded) != 5 {
		t.Errorf("EncodeCRC24 length = %d, want 5", len(encoded))
	}
}

func TestArmor_SignatureFormat(t *testing.T) {
	data := []byte{0x04, 0x00, 0x13, 0x08}
	armored := Armor(ArmorSignature, data)

	if !strings.Contains(armored, "-----BEGIN PGP SIGNATURE-----") {
		t.Error("missing BEGIN marker")
	}
	if !strings.Contains(armored, "-----END PGP SIGNATURE-----") {
		t.Error("missing END marker")
	}
	// Should contain base64-encoded data
	if !strings.Contains(armored, base64.StdEncoding.EncodeToString(data)) {
		t.Error("missing base64 data")
	}
	// Should contain CRC
	if !strings.Contains(armored, "=") {
		t.Error("missing CRC line")
	}
}

func TestArmor_LineWrapping(t *testing.T) {
	// Create data that will produce > 64 chars of base64
	data := make([]byte, 100) // ~136 base64 chars
	for i := range data {
		data[i] = byte(i)
	}
	armored := Armor(ArmorPublicKey, data)
	lines := strings.Split(armored, "\n")

	// Check that no base64 line exceeds 64 characters
	for _, line := range lines {
		if strings.HasPrefix(line, "-----") || strings.HasPrefix(line, "=") || line == "" {
			continue
		}
		if len(line) > 64 {
			t.Errorf("base64 line exceeds 64 chars: length %d", len(line))
		}
	}
}

func TestArmorSig(t *testing.T) {
	sig := []byte{0x01, 0x02}
	armored := ArmorSig(sig)
	if !strings.Contains(armored, "PGP SIGNATURE") {
		t.Error("ArmorSig should produce PGP SIGNATURE armor")
	}
}

func TestDearmor_NotArmored(t *testing.T) {
	raw := []byte{0x01, 0x02, 0x03}
	decoded, armorType, err := Dearmor(raw)
	if err != nil {
		t.Fatalf("Dearmor error: %v", err)
	}
	if armorType != "" {
		t.Errorf("armor type should be empty for non-armored, got %q", armorType)
	}
	if string(decoded) != string(raw) {
		t.Error("non-armored data should be returned as-is")
	}
}

func TestDearmor_Roundtrip(t *testing.T) {
	original := []byte{0x04, 0x00, 0x13, 0x08, 0xAA, 0xBB, 0xCC}
	armored := Armor(ArmorSignature, original)

	decoded, armorType, err := Dearmor([]byte(armored))
	if err != nil {
		t.Fatalf("Dearmor error: %v", err)
	}
	if armorType != ArmorSignature {
		t.Errorf("armor type = %q, want %q", armorType, ArmorSignature)
	}
	if string(decoded) != string(original) {
		t.Errorf("roundtrip mismatch: got %x, want %x", decoded, original)
	}
}

func TestDearmor_LargePayload(t *testing.T) {
	// Test with data that produces multi-line base64
	data := make([]byte, 200)
	for i := range data {
		data[i] = byte(i)
	}
	armored := Armor(ArmorSignature, data)

	decoded, armorType, err := Dearmor([]byte(armored))
	if err != nil {
		t.Fatalf("Dearmor large payload error: %v", err)
	}
	if armorType != ArmorSignature {
		t.Errorf("armor type = %q, want %q", armorType, ArmorSignature)
	}
	if string(decoded) != string(data) {
		t.Errorf("decoded length = %d, want %d", len(decoded), len(data))
	}
}

func TestDearmor_MissingEndMarker(t *testing.T) {
	armored := "-----BEGIN PGP SIGNATURE-----\nBASE64DATA\n"
	_, _, err := Dearmor([]byte(armored))
	if err == nil {
		t.Error("expected error for missing END marker")
	}
}

func TestDearmor_MalformedBeginMarker(t *testing.T) {
	armored := "-----BEGIN PGP \nBASE64DATA\n"
	_, _, err := Dearmor([]byte(armored))
	if err == nil {
		t.Error("expected error for malformed BEGIN marker")
	}
}

func TestDearmor_PublicKeyBlock(t *testing.T) {
	data := []byte{0x99, 0x00, 0x20}
	armored := Armor(ArmorPublicKey, data)

	decoded, armorType, err := Dearmor([]byte(armored))
	if err != nil {
		t.Fatalf("Dearmor public key error: %v", err)
	}
	if armorType != ArmorPublicKey {
		t.Errorf("armor type = %q, want %q", armorType, ArmorPublicKey)
	}
	if string(decoded) != string(data) {
		t.Error("decoded data mismatch")
	}
}

func TestDearmor_MessageBlock(t *testing.T) {
	data := []byte{0xC1, 0x10, 0x03}
	armored := Armor(ArmorMessage, data)

	decoded, armorType, err := Dearmor([]byte(armored))
	if err != nil {
		t.Fatalf("Dearmor message error: %v", err)
	}
	if armorType != ArmorMessage {
		t.Errorf("armor type = %q, want %q", armorType, ArmorMessage)
	}
	if string(decoded) != string(data) {
		t.Error("decoded data mismatch")
	}
}
