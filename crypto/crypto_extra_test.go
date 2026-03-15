package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"
)

// ── GenerateRandomBytes ──────────────────────────────────────────────

func TestGenerateRandomBytes_ValidLength(t *testing.T) {
	for _, n := range []int{1, 16, 32, 64, 128} {
		b, err := GenerateRandomBytes(n)
		if err != nil {
			t.Fatalf("GenerateRandomBytes(%d) error = %v", n, err)
		}
		if len(b) != n {
			t.Errorf("GenerateRandomBytes(%d) returned %d bytes", n, len(b))
		}
	}
}

func TestGenerateRandomBytes_NonZero(t *testing.T) {
	b, err := GenerateRandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	allZero := true
	for _, v := range b {
		if v != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("GenerateRandomBytes(32) returned all zeros (extremely unlikely)")
	}
}

func TestGenerateRandomBytes_Unique(t *testing.T) {
	a, _ := GenerateRandomBytes(32)
	b, _ := GenerateRandomBytes(32)
	if string(a) == string(b) {
		t.Error("two GenerateRandomBytes(32) calls returned identical bytes")
	}
}

// ── Encrypt / Decrypt edge cases ─────────────────────────────────────

func TestEncrypt_InvalidKeySize(t *testing.T) {
	_, _, err := Encrypt(make([]byte, 16), []byte("hello"), nil)
	if err != ErrInvalidKeySize {
		t.Errorf("Encrypt with short key: got %v, want ErrInvalidKeySize", err)
	}
}

func TestDecrypt_InvalidKeySize(t *testing.T) {
	_, err := Decrypt(make([]byte, 16), make([]byte, NonceSize), []byte("ct"), nil)
	if err != ErrInvalidKeySize {
		t.Errorf("Decrypt with short key: got %v, want ErrInvalidKeySize", err)
	}
}

func TestDecrypt_InvalidNonceSize(t *testing.T) {
	_, err := Decrypt(make([]byte, KeySize), make([]byte, 8), []byte("ct"), nil)
	if err != ErrInvalidNonceSize {
		t.Errorf("Decrypt with short nonce: got %v, want ErrInvalidNonceSize", err)
	}
}

func TestDecrypt_CorruptedCiphertext(t *testing.T) {
	key, _ := GenerateRandomBytes(KeySize)
	ct, nonce, err := Encrypt(key, []byte("secret"), nil)
	if err != nil {
		t.Fatal(err)
	}
	ct[0] ^= 0xFF
	_, err = Decrypt(key, nonce, ct, nil)
	if err != ErrDecryptionFailed {
		t.Errorf("Decrypt corrupted ct: got %v, want ErrDecryptionFailed", err)
	}
}

func TestEncryptDecrypt_EmptyPlaintext(t *testing.T) {
	key, _ := GenerateRandomBytes(KeySize)
	ct, nonce, err := Encrypt(key, []byte{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Decrypt(key, nonce, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(pt) != 0 {
		t.Errorf("expected empty plaintext, got %d bytes", len(pt))
	}
}

func TestEncryptDecrypt_WithAAD(t *testing.T) {
	key, _ := GenerateRandomBytes(KeySize)
	aad := []byte("request-id-123")
	ct, nonce, err := Encrypt(key, []byte("payload"), aad)
	if err != nil {
		t.Fatal(err)
	}

	// Decrypt with correct AAD
	pt, err := Decrypt(key, nonce, ct, aad)
	if err != nil {
		t.Fatalf("Decrypt with correct AAD: %v", err)
	}
	if string(pt) != "payload" {
		t.Errorf("plaintext = %q, want payload", pt)
	}

	// Decrypt with wrong AAD should fail
	_, err = Decrypt(key, nonce, ct, []byte("wrong-aad"))
	if err != ErrDecryptionFailed {
		t.Errorf("Decrypt with wrong AAD: got %v, want ErrDecryptionFailed", err)
	}
}

func TestEncrypt_GeneratesUniqueNonces(t *testing.T) {
	key, _ := GenerateRandomBytes(KeySize)
	_, nonce1, _ := Encrypt(key, []byte("a"), nil)
	_, nonce2, _ := Encrypt(key, []byte("a"), nil)
	if string(nonce1) == string(nonce2) {
		t.Error("two Encrypt calls produced the same nonce")
	}
}

// ── SharedSecret edge cases ──────────────────────────────────────────

func TestSharedSecret_WrongPrivateKeySize(t *testing.T) {
	_, err := SharedSecret(make([]byte, 16), make([]byte, PublicKeySize))
	if err != ErrInvalidKeySize {
		t.Errorf("SharedSecret with short private key: got %v, want ErrInvalidKeySize", err)
	}
}

func TestSharedSecret_WrongPublicKeySize(t *testing.T) {
	_, err := SharedSecret(make([]byte, PrivateKeySize), make([]byte, 16))
	if err != ErrInvalidKeySize {
		t.Errorf("SharedSecret with short public key: got %v, want ErrInvalidKeySize", err)
	}
}

func TestSharedSecret_Symmetric(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()

	secret1, err := SharedSecret(kp1.PrivateKey[:], kp2.PublicKey[:])
	if err != nil {
		t.Fatal(err)
	}
	secret2, err := SharedSecret(kp2.PrivateKey[:], kp1.PublicKey[:])
	if err != nil {
		t.Fatal(err)
	}
	if string(secret1) != string(secret2) {
		t.Error("ECDH shared secrets should be symmetric")
	}
}

// ── DeriveRequestKey / DeriveResponseKey ─────────────────────────────

func TestDeriveRequestKey_RoundTrip(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()
	requestID := []byte("test-request-id!")

	// Both sides should derive the same key
	key1, err := DeriveRequestKey(kp1.PrivateKey[:], kp2.PublicKey[:], requestID)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := DeriveRequestKey(kp2.PrivateKey[:], kp1.PublicKey[:], requestID)
	if err != nil {
		t.Fatal(err)
	}
	if string(key1) != string(key2) {
		t.Error("both parties should derive the same request key")
	}
	if len(key1) != KeySize {
		t.Errorf("key length = %d, want %d", len(key1), KeySize)
	}
}

func TestDeriveResponseKey_RoundTrip(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()
	requestID := []byte("test-request-id!")

	key1, err := DeriveResponseKey(kp1.PrivateKey[:], kp2.PublicKey[:], requestID)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := DeriveResponseKey(kp2.PrivateKey[:], kp1.PublicKey[:], requestID)
	if err != nil {
		t.Fatal(err)
	}
	if string(key1) != string(key2) {
		t.Error("both parties should derive the same response key")
	}
}

func TestDeriveRequestKey_DifferentFromResponseKey(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()
	requestID := []byte("test-request-id!")

	reqKey, _ := DeriveRequestKey(kp1.PrivateKey[:], kp2.PublicKey[:], requestID)
	respKey, _ := DeriveResponseKey(kp1.PrivateKey[:], kp2.PublicKey[:], requestID)
	if string(reqKey) == string(respKey) {
		t.Error("request and response keys should differ (different HKDF info)")
	}
}

func TestDeriveRequestKey_DifferentRequestIDs(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()

	key1, _ := DeriveRequestKey(kp1.PrivateKey[:], kp2.PublicKey[:], []byte("id-1"))
	key2, _ := DeriveRequestKey(kp1.PrivateKey[:], kp2.PublicKey[:], []byte("id-2"))
	if string(key1) == string(key2) {
		t.Error("different request IDs should yield different keys")
	}
}

// ── GenerateKeyPair ──────────────────────────────────────────────────

func TestGenerateKeyPair_ValidKeys(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	if len(kp.PrivateKey) != PrivateKeySize {
		t.Errorf("private key size = %d, want %d", len(kp.PrivateKey), PrivateKeySize)
	}
	if len(kp.PublicKey) != PublicKeySize {
		t.Errorf("public key size = %d, want %d", len(kp.PublicKey), PublicKeySize)
	}

	// Public key should start with 0x02 or 0x03 (compressed format)
	if kp.PublicKey[0] != 0x02 && kp.PublicKey[0] != 0x03 {
		t.Errorf("compressed public key prefix = 0x%02x, want 0x02 or 0x03", kp.PublicKey[0])
	}
}

func TestGenerateKeyPair_Unique(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()
	if kp1.PrivateKey == kp2.PrivateKey {
		t.Error("two GenerateKeyPair calls produced identical private keys")
	}
}

// ── CompressPublicKey / DecompressPublicKey ───────────────────────────

func TestCompressDecompress_RoundTrip(t *testing.T) {
	kp, _ := GenerateKeyPair()

	// Decompress compressed key → uncompressed
	uncompressed, err := DecompressPublicKey(kp.PublicKey[:])
	if err != nil {
		t.Fatal(err)
	}
	if len(uncompressed) != UncompressedPublicKeySize {
		t.Errorf("uncompressed size = %d, want %d", len(uncompressed), UncompressedPublicKeySize)
	}
	if uncompressed[0] != 0x04 {
		t.Errorf("uncompressed prefix = 0x%02x, want 0x04", uncompressed[0])
	}

	// Re-compress
	recompressed, err := CompressPublicKey(uncompressed)
	if err != nil {
		t.Fatal(err)
	}
	if string(recompressed) != string(kp.PublicKey[:]) {
		t.Error("compress(decompress(key)) != key")
	}
}

// ── parseAttestDER ───────────────────────────────────────────────────

func TestParseAttestDER_Valid(t *testing.T) {
	// Create a valid DER-encoded signature: 0x30 <total_len> 0x02 <r_len> <r> 0x02 <s_len> <s>
	r := big.NewInt(12345)
	s := big.NewInt(67890)
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	der := []byte{
		0x30, byte(2 + len(rBytes) + 2 + len(sBytes)),
		0x02, byte(len(rBytes)),
	}
	der = append(der, rBytes...)
	der = append(der, 0x02, byte(len(sBytes)))
	der = append(der, sBytes...)

	parsedR, parsedS, err := parseAttestDER(der)
	if err != nil {
		t.Fatalf("parseAttestDER() error = %v", err)
	}
	if parsedR.Cmp(r) != 0 {
		t.Errorf("R = %v, want %v", parsedR, r)
	}
	if parsedS.Cmp(s) != 0 {
		t.Errorf("S = %v, want %v", parsedS, s)
	}
}

func TestParseAttestDER_TooShort(t *testing.T) {
	_, _, err := parseAttestDER([]byte{0x30, 0x01, 0x02})
	if err == nil {
		t.Error("expected error for too-short DER")
	}
}

func TestParseAttestDER_WrongTag(t *testing.T) {
	_, _, err := parseAttestDER([]byte{0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02})
	if err == nil {
		t.Error("expected error for wrong tag")
	}
}

func TestParseAttestDER_MissingRTag(t *testing.T) {
	_, _, err := parseAttestDER([]byte{0x30, 0x06, 0x03, 0x01, 0x01, 0x02, 0x01, 0x02})
	if err == nil {
		t.Error("expected error for missing R tag")
	}
}

func TestParseAttestDER_ROverflow(t *testing.T) {
	// R length extends beyond the buffer
	_, _, err := parseAttestDER([]byte{0x30, 0x06, 0x02, 0xFF, 0x01, 0x02, 0x01, 0x02})
	if err == nil {
		t.Error("expected error for R overflow")
	}
}

func TestParseAttestDER_MissingSTag(t *testing.T) {
	// Valid R but no S tag follows
	_, _, err := parseAttestDER([]byte{0x30, 0x04, 0x02, 0x01, 0x01, 0x03, 0x01, 0x02})
	if err == nil {
		t.Error("expected error for missing S tag")
	}
}

func TestParseAttestDER_SLengthMissing(t *testing.T) {
	// Valid R, S tag present but no length byte
	_, _, err := parseAttestDER([]byte{0x30, 0x03, 0x02, 0x01, 0x01, 0x02})
	if err == nil {
		t.Error("expected error for S length missing")
	}
}

func TestParseAttestDER_SOverflow(t *testing.T) {
	// Valid R, S tag present, S length exceeds buffer
	_, _, err := parseAttestDER([]byte{0x30, 0x05, 0x02, 0x01, 0x01, 0x02, 0xFF})
	if err == nil {
		t.Error("expected error for S overflow")
	}
}

// ── VerifyAttestationSignature ───────────────────────────────────────

func TestVerifyAttestationSignature_DER(t *testing.T) {
	// Generate a real ECDSA key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Compress the public key
	compressedPub := elliptic.MarshalCompressed(elliptic.P256(), privKey.X, privKey.Y)
	if len(compressedPub) != PublicKeySize {
		t.Fatalf("compressed key size = %d", len(compressedPub))
	}

	requestID := []byte("request-id-12345")
	encryptedResponse := []byte("encrypted-response-data")

	// Build message: requestID || SHA256(encryptedResponse)
	responseHash := sha256.Sum256(encryptedResponse)
	message := make([]byte, len(requestID)+32)
	copy(message, requestID)
	copy(message[len(requestID):], responseHash[:])
	msgHash := sha256.Sum256(message)

	// Sign with DER encoding
	sig, err := ecdsa.SignASN1(rand.Reader, privKey, msgHash[:])
	if err != nil {
		t.Fatal(err)
	}

	valid, err := VerifyAttestationSignature(compressedPub, requestID, encryptedResponse, sig)
	if err != nil {
		t.Fatalf("VerifyAttestationSignature() error = %v", err)
	}
	if !valid {
		t.Error("valid DER signature should verify")
	}
}

func TestVerifyAttestationSignature_Raw64(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	compressedPub := elliptic.MarshalCompressed(elliptic.P256(), privKey.X, privKey.Y)
	requestID := []byte("request-id-12345")
	encryptedResponse := []byte("encrypted-response-data")

	responseHash := sha256.Sum256(encryptedResponse)
	message := make([]byte, len(requestID)+32)
	copy(message, requestID)
	copy(message[len(requestID):], responseHash[:])
	msgHash := sha256.Sum256(message)

	// Sign and extract r, s
	r, s, err := ecdsa.Sign(rand.Reader, privKey, msgHash[:])
	if err != nil {
		t.Fatal(err)
	}

	// Build raw 64-byte signature: r || s (padded to 32 bytes each)
	rawSig := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(rawSig[32-len(rBytes):32], rBytes)
	copy(rawSig[64-len(sBytes):64], sBytes)

	valid, err := VerifyAttestationSignature(compressedPub, requestID, encryptedResponse, rawSig)
	if err != nil {
		t.Fatalf("VerifyAttestationSignature() error = %v", err)
	}
	if !valid {
		t.Error("valid raw 64-byte signature should verify")
	}
}

func TestVerifyAttestationSignature_InvalidSignature(t *testing.T) {
	kp, _ := GenerateKeyPair()
	valid, err := VerifyAttestationSignature(kp.PublicKey[:], []byte("req"), []byte("enc"), []byte("invalid"))
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Error("invalid signature should not verify")
	}
}

func TestVerifyAttestationSignature_WrongKeySize(t *testing.T) {
	_, err := VerifyAttestationSignature(make([]byte, 16), []byte("req"), []byte("enc"), []byte("sig"))
	if err == nil {
		t.Error("expected error for wrong key size")
	}
}

// ── DeriveWrappingKey ────────────────────────────────────────────────

func TestDeriveWrappingKey_ValidOutput(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()
	requestID := []byte("test-request-id!")

	key, err := DeriveWrappingKey(kp1.PrivateKey[:], kp2.PublicKey[:], requestID)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != KeySize {
		t.Errorf("wrapping key size = %d, want %d", len(key), KeySize)
	}
}

func TestDeriveWrappingKey_Symmetric(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()
	requestID := []byte("test-request-id!")

	key1, _ := DeriveWrappingKey(kp1.PrivateKey[:], kp2.PublicKey[:], requestID)
	key2, _ := DeriveWrappingKey(kp2.PrivateKey[:], kp1.PublicKey[:], requestID)
	if string(key1) != string(key2) {
		t.Error("wrapping key derivation should be symmetric")
	}
}

func TestDeriveWrappingKey_DifferentFromRequestKey(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()
	requestID := []byte("test-request-id!")

	wrapKey, _ := DeriveWrappingKey(kp1.PrivateKey[:], kp2.PublicKey[:], requestID)
	reqKey, _ := DeriveRequestKey(kp1.PrivateKey[:], kp2.PublicKey[:], requestID)
	if string(wrapKey) == string(reqKey) {
		t.Error("wrapping key and request key should differ (different HKDF info)")
	}
}

func TestDeriveWrappingKey_InvalidKey(t *testing.T) {
	_, err := DeriveWrappingKey(make([]byte, 16), make([]byte, PublicKeySize), []byte("id"))
	if err != ErrInvalidKeySize {
		t.Errorf("DeriveWrappingKey with short key: got %v, want ErrInvalidKeySize", err)
	}
}

// ── EncryptForMultipleDevices / DecryptFromMultiDevice ────────────────

func TestMultiDevice_RoundTrip_SingleDevice(t *testing.T) {
	device, _ := GenerateKeyPair()
	pubHex := hex.EncodeToString(device.PublicKey[:])
	requestID := []byte("multi-device-req")
	plaintext := []byte(`{"action":"approve","tool":"bash"}`)

	devices := []DeviceKey{{
		EncryptionPublicKeyHex: pubHex,
		PublicKey:              device.PublicKey[:],
	}}

	payload, err := EncryptForMultipleDevices(plaintext, devices, requestID)
	if err != nil {
		t.Fatalf("EncryptForMultipleDevices() error = %v", err)
	}
	if len(payload.WrappedKeys) != 1 {
		t.Fatalf("wrapped keys count = %d, want 1", len(payload.WrappedKeys))
	}
	if payload.WrappedKeys[0].EncryptionPublicKeyHex != pubHex {
		t.Error("wrapped key public key hex mismatch")
	}

	// Decrypt
	decrypted, err := DecryptFromMultiDevice(payload, pubHex, device.PrivateKey[:], requestID)
	if err != nil {
		t.Fatalf("DecryptFromMultiDevice() error = %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestMultiDevice_RoundTrip_MultipleDevices(t *testing.T) {
	device1, _ := GenerateKeyPair()
	device2, _ := GenerateKeyPair()
	device3, _ := GenerateKeyPair()

	pub1Hex := hex.EncodeToString(device1.PublicKey[:])
	pub2Hex := hex.EncodeToString(device2.PublicKey[:])
	pub3Hex := hex.EncodeToString(device3.PublicKey[:])

	requestID := []byte("multi-device-req")
	plaintext := []byte("secret-for-all-devices")

	devices := []DeviceKey{
		{EncryptionPublicKeyHex: pub1Hex, PublicKey: device1.PublicKey[:]},
		{EncryptionPublicKeyHex: pub2Hex, PublicKey: device2.PublicKey[:]},
		{EncryptionPublicKeyHex: pub3Hex, PublicKey: device3.PublicKey[:]},
	}

	payload, err := EncryptForMultipleDevices(plaintext, devices, requestID)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload.WrappedKeys) != 3 {
		t.Fatalf("wrapped keys count = %d, want 3", len(payload.WrappedKeys))
	}

	// All three devices should be able to decrypt
	for _, tc := range []struct {
		name string
		hex  string
		priv [PrivateKeySize]byte
	}{
		{"device1", pub1Hex, device1.PrivateKey},
		{"device2", pub2Hex, device2.PrivateKey},
		{"device3", pub3Hex, device3.PrivateKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dec, err := DecryptFromMultiDevice(payload, tc.hex, tc.priv[:], requestID)
			if err != nil {
				t.Fatalf("DecryptFromMultiDevice() error = %v", err)
			}
			if string(dec) != string(plaintext) {
				t.Errorf("decrypted = %q, want %q", dec, plaintext)
			}
		})
	}
}

func TestMultiDevice_DecryptWrongDevice(t *testing.T) {
	device, _ := GenerateKeyPair()
	wrongDevice, _ := GenerateKeyPair()

	pubHex := hex.EncodeToString(device.PublicKey[:])
	wrongPubHex := hex.EncodeToString(wrongDevice.PublicKey[:])
	requestID := []byte("multi-device-req")

	payload, _ := EncryptForMultipleDevices([]byte("data"), []DeviceKey{
		{EncryptionPublicKeyHex: pubHex, PublicKey: device.PublicKey[:]},
	}, requestID)

	// Try to decrypt with a device whose public key hex isn't in the wrapped keys
	_, err := DecryptFromMultiDevice(payload, wrongPubHex, wrongDevice.PrivateKey[:], requestID)
	if err != ErrDecryptionFailed {
		t.Errorf("expected ErrDecryptionFailed, got %v", err)
	}
}

func TestMultiDevice_EncryptEmptyDevices(t *testing.T) {
	_, err := EncryptForMultipleDevices([]byte("data"), nil, []byte("id"))
	if err != ErrInvalidKeySize {
		t.Errorf("expected ErrInvalidKeySize for empty devices, got %v", err)
	}
}

func TestMultiDevice_SkipsInvalidDeviceKeys(t *testing.T) {
	validDevice, _ := GenerateKeyPair()
	validHex := hex.EncodeToString(validDevice.PublicKey[:])
	requestID := []byte("multi-device-req")

	devices := []DeviceKey{
		{EncryptionPublicKeyHex: "invalid", PublicKey: []byte("too-short")}, // Invalid — skipped
		{EncryptionPublicKeyHex: validHex, PublicKey: validDevice.PublicKey[:]},
	}

	payload, err := EncryptForMultipleDevices([]byte("data"), devices, requestID)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload.WrappedKeys) != 1 {
		t.Errorf("wrapped keys count = %d, want 1 (invalid device should be skipped)", len(payload.WrappedKeys))
	}
}

func TestMultiDevice_WrongRequestID(t *testing.T) {
	device, _ := GenerateKeyPair()
	pubHex := hex.EncodeToString(device.PublicKey[:])

	payload, _ := EncryptForMultipleDevices([]byte("data"), []DeviceKey{
		{EncryptionPublicKeyHex: pubHex, PublicKey: device.PublicKey[:]},
	}, []byte("correct-id"))

	// Decrypt with wrong request ID — AAD mismatch
	_, err := DecryptFromMultiDevice(payload, pubHex, device.PrivateKey[:], []byte("wrong-id"))
	if err == nil {
		t.Error("expected error for wrong request ID (AAD mismatch)")
	}
}

// ── verifyAttestDER / verifyAttestRaw ────────────────────────────────

func TestVerifyAttestDER_NotDER(t *testing.T) {
	pubKey := &ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(1), Y: big.NewInt(1)}
	result := verifyAttestDER(pubKey, []byte("hash"), []byte{0x01, 0x02, 0x03})
	if result {
		t.Error("non-DER signature should not verify")
	}
}

func TestVerifyAttestRaw_WrongLength(t *testing.T) {
	pubKey := &ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(1), Y: big.NewInt(1)}
	result := verifyAttestRaw(pubKey, []byte("hash"), []byte{0x01, 0x02, 0x03})
	if result {
		t.Error("non-64-byte signature should not verify")
	}
}
