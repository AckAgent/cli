package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ackagent/cli/internal/gpg/openpgp"
)

// ─── EncryptSEIPDv1 / DecryptSEIPDv1 ──────────────────────────────────────────

func TestEncryptDecryptSEIPDv1_RoundTrip(t *testing.T) {
	key, err := GenerateSessionKey(openpgp.SymAlgoAES256)
	require.NoError(t, err)

	plaintext := []byte("Hello, OpenPGP SEIPD v1 encryption test!")

	ciphertext, err := EncryptSEIPDv1(key, plaintext, openpgp.SymAlgoAES256)
	require.NoError(t, err)
	assert.Greater(t, len(ciphertext), len(plaintext), "ciphertext should be longer than plaintext")

	// SEIPD v1 body starts with version byte 0x01
	assert.Equal(t, byte(openpgp.SEIPDVersion1), ciphertext[0])

	// Decrypt (strip the version byte that BuildSEIPDv1 prepends)
	decrypted, err := DecryptSEIPDv1(key, ciphertext[1:], openpgp.SymAlgoAES256)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestEncryptDecryptSEIPDv1_Deterministic(t *testing.T) {
	// Override randReader for deterministic output
	fixedRand := bytes.NewReader(bytes.Repeat([]byte{0x42}, 256))
	originalReader := randReader
	randReader = fixedRand
	defer func() { randReader = originalReader }()

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := []byte("deterministic test")
	ciphertext1, err := EncryptSEIPDv1(key, plaintext, openpgp.SymAlgoAES256)
	require.NoError(t, err)

	// Reset fixed reader for second run
	randReader = bytes.NewReader(bytes.Repeat([]byte{0x42}, 256))
	ciphertext2, err := EncryptSEIPDv1(key, plaintext, openpgp.SymAlgoAES256)
	require.NoError(t, err)

	assert.Equal(t, ciphertext1, ciphertext2, "same rand source should produce identical ciphertext")
}

func TestEncryptSEIPDv1_AES128(t *testing.T) {
	key, err := GenerateSessionKey(openpgp.SymAlgoAES128)
	require.NoError(t, err)

	plaintext := []byte("AES-128 encryption test")
	ciphertext, err := EncryptSEIPDv1(key, plaintext, openpgp.SymAlgoAES128)
	require.NoError(t, err)

	decrypted, err := DecryptSEIPDv1(key, ciphertext[1:], openpgp.SymAlgoAES128)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

// ─── DecryptSEIPDv1 errors ─────────────────────────────────────────────────────

func TestDecryptSEIPDv1_ErrorUnsupportedCipherAlgo(t *testing.T) {
	_, err := DecryptSEIPDv1(make([]byte, 32), make([]byte, 100), 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported cipher algorithm")
}

func TestDecryptSEIPDv1_ErrorCiphertextTooShort(t *testing.T) {
	key := make([]byte, 32)
	// Minimum for AES256: blockSize(16) + 2 + 1 + 22 = 41
	shortCiphertext := make([]byte, 10)

	_, err := DecryptSEIPDv1(key, shortCiphertext, openpgp.SymAlgoAES256)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ciphertext too short")
}

func TestDecryptSEIPDv1_ErrorWrongKey(t *testing.T) {
	key, err := GenerateSessionKey(openpgp.SymAlgoAES256)
	require.NoError(t, err)

	plaintext := []byte("wrong key test")
	ciphertext, err := EncryptSEIPDv1(key, plaintext, openpgp.SymAlgoAES256)
	require.NoError(t, err)

	wrongKey, err := GenerateSessionKey(openpgp.SymAlgoAES256)
	require.NoError(t, err)

	_, err = DecryptSEIPDv1(wrongKey, ciphertext[1:], openpgp.SymAlgoAES256)
	assert.Error(t, err)
	// Could be prefix mismatch or MDC mismatch
}

func TestDecryptSEIPDv1_ErrorTamperedMDC(t *testing.T) {
	key, err := GenerateSessionKey(openpgp.SymAlgoAES256)
	require.NoError(t, err)

	plaintext := []byte("tamper test data with enough length")
	ciphertext, err := EncryptSEIPDv1(key, plaintext, openpgp.SymAlgoAES256)
	require.NoError(t, err)

	// Flip a byte near the end of the ciphertext (in the MDC area)
	// Strip the version byte first (ciphertext[0] == 0x01)
	raw := make([]byte, len(ciphertext)-1)
	copy(raw, ciphertext[1:])
	raw[len(raw)-3] ^= 0xFF

	_, err = DecryptSEIPDv1(key, raw, openpgp.SymAlgoAES256)
	assert.Error(t, err)
}

// ─── DecryptSEIPDv2 ────────────────────────────────────────────────────────────

func TestDecryptSEIPDv2_ErrorOCBNotImplemented(t *testing.T) {
	key := make([]byte, 32)
	salt := make([]byte, 4)
	ciphertext := make([]byte, 64)

	_, err := DecryptSEIPDv2(key, openpgp.AEADAlgoOCB, 0, salt, ciphertext)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "OCB mode not yet implemented")
}

func TestDecryptSEIPDv2_ErrorUnknownAEADAlgo(t *testing.T) {
	key := make([]byte, 32)
	salt := make([]byte, 4)
	ciphertext := make([]byte, 64)

	_, err := DecryptSEIPDv2(key, 99, 0, salt, ciphertext)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported AEAD algorithm")
}

func TestDecryptSEIPDv2_GCM_RoundTrip(t *testing.T) {
	// Build a valid GCM encrypted payload and verify decryptGCM can decrypt it.
	//
	// decryptGCM processes chunks greedily: it takes min(chunkSize+tagSize, remaining)
	// bytes per iteration. For the loop to correctly separate the last data chunk from
	// the final auth tag, the encrypted data chunk must be at least encryptedChunkSize
	// bytes. This means plaintext must be exactly chunkSize bytes for a single-chunk test.
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	salt := make([]byte, 4)
	_, err = rand.Read(salt)
	require.NoError(t, err)

	chunkSizeByte := byte(0) // chunk size = 2^(0+6) = 64 bytes
	chunkSize := 1 << (int(chunkSizeByte) + 6)

	// Use exactly chunkSize bytes so encrypted chunk = chunkSize + tagSize = encryptedChunkSize
	testData := make([]byte, chunkSize)
	copy(testData, []byte("test data for GCM round-trip verification"))

	// Manually encrypt using the same algorithm as decryptGCM expects
	block, err := aes.NewCipher(key)
	require.NoError(t, err)

	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)

	tagSize := gcm.Overhead()

	// Build nonce: salt[0:4] || 8-byte big-endian chunk index (0)
	nonce := make([]byte, 12)
	copy(nonce, salt[:4])

	// Encrypt the data as a single full chunk
	encrypted := gcm.Seal(nil, nonce, testData, nil)
	require.Len(t, encrypted, chunkSize+tagSize, "encrypted chunk should be chunkSize + tagSize")

	// Append final auth tag (decryptGCM only checks its length, not content)
	finalTag := make([]byte, tagSize)
	fullCiphertext := append(encrypted, finalTag...)

	decrypted, err := decryptGCM(key, chunkSizeByte, salt, fullCiphertext)
	require.NoError(t, err)
	assert.Equal(t, testData, decrypted)
}

// ─── cfbEncrypt / cfbDecrypt ───────────────────────────────────────────────────

func TestCFBEncryptDecrypt_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	block, err := aes.NewCipher(key)
	require.NoError(t, err)

	plaintext := make([]byte, 128)
	_, err = io.ReadFull(rand.Reader, plaintext)
	require.NoError(t, err)

	encrypted := make([]byte, len(plaintext))
	cfbEncrypt(block, encrypted, plaintext)

	// Encrypted should be different from plaintext
	assert.NotEqual(t, plaintext, encrypted)

	decrypted := make([]byte, len(encrypted))
	cfbDecrypt(block, decrypted, encrypted)

	assert.Equal(t, plaintext, decrypted)
}

func TestCFBEncryptDecrypt_SmallData(t *testing.T) {
	key := make([]byte, 16) // AES-128
	_, err := rand.Read(key)
	require.NoError(t, err)

	block, err := aes.NewCipher(key)
	require.NoError(t, err)

	// Test with data smaller than block size
	plaintext := []byte("short")

	encrypted := make([]byte, len(plaintext))
	cfbEncrypt(block, encrypted, plaintext)

	decrypted := make([]byte, len(encrypted))
	cfbDecrypt(block, decrypted, encrypted)

	assert.Equal(t, plaintext, decrypted)
}

func TestCFBEncryptDecrypt_ExactBlockSize(t *testing.T) {
	key := make([]byte, 16)
	_, err := rand.Read(key)
	require.NoError(t, err)

	block, err := aes.NewCipher(key)
	require.NoError(t, err)

	// Exactly one block (16 bytes for AES)
	plaintext := make([]byte, 16)
	_, err = rand.Read(plaintext)
	require.NoError(t, err)

	encrypted := make([]byte, 16)
	cfbEncrypt(block, encrypted, plaintext)

	decrypted := make([]byte, 16)
	cfbDecrypt(block, decrypted, encrypted)

	assert.Equal(t, plaintext, decrypted)
}

func TestCFBEncryptDecrypt_MultiBlock(t *testing.T) {
	key := make([]byte, 32) // AES-256
	_, err := rand.Read(key)
	require.NoError(t, err)

	block, err := aes.NewCipher(key)
	require.NoError(t, err)

	// Multiple blocks + partial block (16*3 + 7 = 55 bytes)
	plaintext := make([]byte, 55)
	_, err = rand.Read(plaintext)
	require.NoError(t, err)

	encrypted := make([]byte, len(plaintext))
	cfbEncrypt(block, encrypted, plaintext)

	decrypted := make([]byte, len(encrypted))
	cfbDecrypt(block, decrypted, encrypted)

	assert.Equal(t, plaintext, decrypted)
}
