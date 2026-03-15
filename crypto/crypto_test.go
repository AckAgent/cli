package crypto

import (
	"bytes"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Check key sizes
	if len(kp.PrivateKey) != PrivateKeySize {
		t.Errorf("PrivateKey size = %d, want %d", len(kp.PrivateKey), PrivateKeySize)
	}
	if len(kp.PublicKey) != PublicKeySize {
		t.Errorf("PublicKey size = %d, want %d", len(kp.PublicKey), PublicKeySize)
	}

	// Check public key starts with 0x02 or 0x03 (compressed point indicator)
	if kp.PublicKey[0] != 0x02 && kp.PublicKey[0] != 0x03 {
		t.Errorf("PublicKey[0] = 0x%02x, want 0x02 or 0x03 (compressed point)", kp.PublicKey[0])
	}

	// Check public key is not zero
	var zero [PublicKeySize]byte
	if kp.PublicKey == zero {
		t.Error("PublicKey is zero")
	}
}

func TestSharedSecret(t *testing.T) {
	// Generate two key pairs
	alice, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (alice) failed: %v", err)
	}

	bob, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (bob) failed: %v", err)
	}

	// Compute shared secrets
	aliceShared, err := SharedSecret(alice.PrivateKey[:], bob.PublicKey[:])
	if err != nil {
		t.Fatalf("SharedSecret (alice) failed: %v", err)
	}

	bobShared, err := SharedSecret(bob.PrivateKey[:], alice.PublicKey[:])
	if err != nil {
		t.Fatalf("SharedSecret (bob) failed: %v", err)
	}

	// Verify they match
	if !bytes.Equal(aliceShared, bobShared) {
		t.Error("Shared secrets do not match")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, KeySize)
	copy(key, []byte("0123456789abcdef0123456789abcdef"))

	plaintext := []byte("Hello, World!")
	additionalData := []byte("request-id-123")

	// Encrypt
	ciphertext, nonce, err := Encrypt(key, plaintext, additionalData)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if len(nonce) != NonceSize {
		t.Errorf("Nonce size = %d, want %d", len(nonce), NonceSize)
	}

	// Decrypt
	decrypted, err := Decrypt(key, nonce, ciphertext, additionalData)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestDecryptWrongKey(t *testing.T) {
	key1 := make([]byte, KeySize)
	key2 := make([]byte, KeySize)
	copy(key1, []byte("0123456789abcdef0123456789abcdef"))
	copy(key2, []byte("fedcba9876543210fedcba9876543210"))

	plaintext := []byte("Secret message")
	ciphertext, nonce, _ := Encrypt(key1, plaintext, nil)

	// Try to decrypt with wrong key
	_, err := Decrypt(key2, nonce, ciphertext, nil)
	if err != ErrDecryptionFailed {
		t.Errorf("Expected ErrDecryptionFailed, got %v", err)
	}
}

func TestDecryptWrongAAD(t *testing.T) {
	key := make([]byte, KeySize)
	copy(key, []byte("0123456789abcdef0123456789abcdef"))

	plaintext := []byte("Secret message")
	ciphertext, nonce, _ := Encrypt(key, plaintext, []byte("aad1"))

	// Try to decrypt with wrong AAD
	_, err := Decrypt(key, nonce, ciphertext, []byte("aad2"))
	if err != ErrDecryptionFailed {
		t.Errorf("Expected ErrDecryptionFailed, got %v", err)
	}
}

func TestEndToEndEncryption(t *testing.T) {
	// Simulate full E2E flow between iOS (signer) and desktop (requestor)
	// With forward secrecy, desktop uses ephemeral keys per-request

	// 1. iOS has identity key pair (established during pairing)
	ios, _ := GenerateKeyPair() // signer identity

	// 2. Desktop generates ephemeral keypair for this request (forward secrecy)
	desktopEphemeral, _ := GenerateKeyPair()

	// 3. Generate request ID for HKDF salt
	requestID := []byte("0123456789abcdef") // 16 bytes

	// 4. Desktop derives request encryption key
	// Desktop: ECDH(ephemeral_private, ios_identity_public)
	desktopRequestKey, err := DeriveRequestKey(desktopEphemeral.PrivateKey[:], ios.PublicKey[:], requestID)
	if err != nil {
		t.Fatalf("Desktop failed to derive request key: %v", err)
	}

	// 5. iOS derives same request key
	// iOS: ECDH(identity_private, desktop_ephemeral_public)
	iosRequestKey, err := DeriveRequestKey(ios.PrivateKey[:], desktopEphemeral.PublicKey[:], requestID)
	if err != nil {
		t.Fatalf("iOS failed to derive request key: %v", err)
	}

	// Request keys should match
	if !bytes.Equal(desktopRequestKey, iosRequestKey) {
		t.Fatal("Request keys do not match")
	}

	// 6. Desktop encrypts a message
	message := []byte(`{"type":"ssh_sign","data":"base64data"}`)
	ciphertext, nonce, _ := Encrypt(desktopRequestKey, message, nil)

	// 7. iOS decrypts the message
	decrypted, err := Decrypt(iosRequestKey, nonce, ciphertext, nil)
	if err != nil {
		t.Fatalf("iOS failed to decrypt: %v", err)
	}

	if !bytes.Equal(message, decrypted) {
		t.Error("Decrypted message does not match original")
	}

	// 8. iOS generates ephemeral keypair for response
	iosEphemeral, _ := GenerateKeyPair()

	// 9. iOS derives response encryption key
	// iOS: ECDH(ephemeral_private, desktop_ephemeral_public)
	iosResponseKey, err := DeriveResponseKey(iosEphemeral.PrivateKey[:], desktopEphemeral.PublicKey[:], requestID)
	if err != nil {
		t.Fatalf("iOS failed to derive response key: %v", err)
	}

	// 10. Desktop derives same response key
	// Desktop: ECDH(ephemeral_private, ios_ephemeral_public)
	desktopResponseKey, err := DeriveResponseKey(desktopEphemeral.PrivateKey[:], iosEphemeral.PublicKey[:], requestID)
	if err != nil {
		t.Fatalf("Desktop failed to derive response key: %v", err)
	}

	// Response keys should match
	if !bytes.Equal(iosResponseKey, desktopResponseKey) {
		t.Fatal("Response keys do not match")
	}

	// 11. iOS encrypts response
	response := []byte(`{"signature":"base64sig"}`)
	respCiphertext, respNonce, _ := Encrypt(iosResponseKey, response, nil)

	// 12. Desktop decrypts response
	decryptedResp, err := Decrypt(desktopResponseKey, respNonce, respCiphertext, nil)
	if err != nil {
		t.Fatalf("Desktop failed to decrypt response: %v", err)
	}

	if !bytes.Equal(response, decryptedResp) {
		t.Error("Decrypted response does not match original")
	}
}
