package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ackagent/cli/crypto"
	"github.com/ackagent/cli/internal/gpg/openpgp"
)

// ─── aesKeyWrap / aesKeyUnwrap ─────────────────────────────────────────────────

func TestAESKeyWrap_RFC3394TestVector(t *testing.T) {
	// RFC 3394 §4.1 test vector: 128-bit KEK, 128-bit data
	kek, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F")
	plaintext, _ := hex.DecodeString("00112233445566778899AABBCCDDEEFF")
	expectedCiphertext, _ := hex.DecodeString("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")

	ciphertext, err := aesKeyWrap(kek, plaintext)
	require.NoError(t, err)
	assert.Equal(t, expectedCiphertext, ciphertext)

	// Unwrap and verify
	unwrapped, err := aesKeyUnwrap(kek, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, unwrapped)
}

func TestAESKeyWrap_RoundTrip_RandomData(t *testing.T) {
	kek := make([]byte, 32) // AES-256 KEK
	_, err := rand.Read(kek)
	require.NoError(t, err)

	plaintext := make([]byte, 32) // 32-byte data (4 blocks of 8)
	_, err = rand.Read(plaintext)
	require.NoError(t, err)

	ciphertext, err := aesKeyWrap(kek, plaintext)
	require.NoError(t, err)
	assert.Len(t, ciphertext, len(plaintext)+8, "ciphertext should be plaintext + 8 bytes (IV)")

	unwrapped, err := aesKeyUnwrap(kek, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, unwrapped)
}

func TestAESKeyWrap_ErrorPlaintextNotMultipleOf8(t *testing.T) {
	kek := make([]byte, 16)
	plaintext := make([]byte, 13) // not multiple of 8

	_, err := aesKeyWrap(kek, plaintext)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "multiple of 8")
}

func TestAESKeyUnwrap_ErrorCiphertextTooShort(t *testing.T) {
	kek := make([]byte, 16)
	shortCiphertext := make([]byte, 16) // less than 24

	_, err := aesKeyUnwrap(kek, shortCiphertext)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid ciphertext length")
}

func TestAESKeyUnwrap_ErrorWrongKEK(t *testing.T) {
	kek := make([]byte, 16)
	_, err := rand.Read(kek)
	require.NoError(t, err)

	plaintext := make([]byte, 16)
	_, err = rand.Read(plaintext)
	require.NoError(t, err)

	ciphertext, err := aesKeyWrap(kek, plaintext)
	require.NoError(t, err)

	// Use a different KEK for unwrap
	wrongKEK := make([]byte, 16)
	_, err = rand.Read(wrongKEK)
	require.NoError(t, err)

	_, err = aesKeyUnwrap(wrongKEK, ciphertext)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "IV mismatch")
}

// ─── deriveKEK ─────────────────────────────────────────────────────────────────

func TestDeriveKEK_Determinism(t *testing.T) {
	sharedSecret := make([]byte, 32)
	_, err := rand.Read(sharedSecret)
	require.NoError(t, err)

	fingerprint := make([]byte, 20)
	_, err = rand.Read(fingerprint)
	require.NoError(t, err)

	kek1, err := deriveKEK(sharedSecret, openpgp.HashAlgoSHA256, openpgp.SymAlgoAES256, fingerprint, openpgp.OIDP256)
	require.NoError(t, err)

	kek2, err := deriveKEK(sharedSecret, openpgp.HashAlgoSHA256, openpgp.SymAlgoAES256, fingerprint, openpgp.OIDP256)
	require.NoError(t, err)

	assert.Equal(t, kek1, kek2, "same inputs must produce same KEK")
	assert.Len(t, kek1, 32, "AES-256 KEK should be 32 bytes")
}

func TestDeriveKEK_AES128ProducesShorterKey(t *testing.T) {
	sharedSecret := make([]byte, 32)
	_, err := rand.Read(sharedSecret)
	require.NoError(t, err)

	fingerprint := make([]byte, 20)

	kek, err := deriveKEK(sharedSecret, openpgp.HashAlgoSHA256, openpgp.SymAlgoAES128, fingerprint, openpgp.OIDP256)
	require.NoError(t, err)
	assert.Len(t, kek, 16, "AES-128 KEK should be 16 bytes")
}

func TestDeriveKEK_ErrorUnsupportedHashAlgo(t *testing.T) {
	sharedSecret := make([]byte, 32)
	fingerprint := make([]byte, 20)

	_, err := deriveKEK(sharedSecret, 99, openpgp.SymAlgoAES256, fingerprint, openpgp.OIDP256)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported hash algorithm")
}

func TestDeriveKEK_ErrorUnsupportedSymAlgo(t *testing.T) {
	sharedSecret := make([]byte, 32)
	fingerprint := make([]byte, 20)

	_, err := deriveKEK(sharedSecret, openpgp.HashAlgoSHA256, 0, fingerprint, openpgp.OIDP256)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported symmetric algorithm")
}

// ─── WrapSessionKey / UnwrapSessionKey ─────────────────────────────────────────

func TestWrapUnwrapSessionKey_RoundTrip(t *testing.T) {
	// Generate a P-256 key pair
	curve := ecdh.P256()
	privateKey, err := curve.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Compress public key to 33-byte SEC1 format (as stored in config)
	publicKeyBytes, err := crypto.CompressPublicKey(privateKey.PublicKey().Bytes())
	require.NoError(t, err)
	require.Len(t, publicKeyBytes, 33)

	params := &ECDHParams{
		HashAlgo:  openpgp.HashAlgoSHA256,
		SymAlgo:   openpgp.SymAlgoAES256,
		PublicKey: publicKeyBytes,
	}

	sessionKey := make([]byte, 32) // AES-256 session key
	_, err = rand.Read(sessionKey)
	require.NoError(t, err)

	fingerprint := make([]byte, 20)
	_, err = rand.Read(fingerprint)
	require.NoError(t, err)

	// Wrap
	ephemeralPoint, wrappedKey, err := WrapSessionKey(params, sessionKey, fingerprint)
	require.NoError(t, err)
	assert.Len(t, ephemeralPoint, 65, "ephemeral point should be 65 bytes (uncompressed P-256)")
	assert.Greater(t, len(wrappedKey), len(sessionKey), "wrapped key should be larger than session key")

	// Unwrap
	recovered, err := UnwrapSessionKey(params, ephemeralPoint, wrappedKey, privateKey, fingerprint)
	require.NoError(t, err)
	assert.Equal(t, sessionKey, recovered)
}

func TestWrapSessionKey_ErrorInvalidPublicKeyLength(t *testing.T) {
	params := &ECDHParams{
		HashAlgo:  openpgp.HashAlgoSHA256,
		SymAlgo:   openpgp.SymAlgoAES256,
		PublicKey: make([]byte, 65), // wrong length (expected 33 compressed)
	}

	_, _, err := WrapSessionKey(params, make([]byte, 32), make([]byte, 20))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid public key length")
}

func TestWrapSessionKey_ErrorInvalidCompressedPrefix(t *testing.T) {
	badKey := make([]byte, 33)
	badKey[0] = 0x00 // invalid prefix (not 0x02/0x03)

	params := &ECDHParams{
		HashAlgo:  openpgp.HashAlgoSHA256,
		SymAlgo:   openpgp.SymAlgoAES256,
		PublicKey: badKey,
	}

	_, _, err := WrapSessionKey(params, make([]byte, 32), make([]byte, 20))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decompress")
}

// ─── BuildSessionKeyWithChecksum / ParseSessionKeyWithChecksum ─────────────────

func TestBuildParseSessionKeyWithChecksum_RoundTrip(t *testing.T) {
	sessionKey := make([]byte, 32)
	_, err := rand.Read(sessionKey)
	require.NoError(t, err)

	data := BuildSessionKeyWithChecksum(openpgp.SymAlgoAES256, sessionKey)

	// Verify format: length should be multiple of 8 (PKCS5 padded)
	assert.Equal(t, 0, len(data)%8, "output must be a multiple of 8 bytes (PKCS5 padded)")

	algo, recovered, err := ParseSessionKeyWithChecksum(data)
	require.NoError(t, err)
	assert.Equal(t, byte(openpgp.SymAlgoAES256), algo)
	assert.Equal(t, sessionKey, recovered)
}

func TestBuildParseSessionKeyWithChecksum_AES128(t *testing.T) {
	sessionKey := make([]byte, 16)
	_, err := rand.Read(sessionKey)
	require.NoError(t, err)

	data := BuildSessionKeyWithChecksum(openpgp.SymAlgoAES128, sessionKey)
	assert.Equal(t, 0, len(data)%8)

	algo, recovered, err := ParseSessionKeyWithChecksum(data)
	require.NoError(t, err)
	assert.Equal(t, byte(openpgp.SymAlgoAES128), algo)
	assert.Equal(t, sessionKey, recovered)
}

func TestParseSessionKeyWithChecksum_ErrorDataTooShort(t *testing.T) {
	_, _, err := ParseSessionKeyWithChecksum([]byte{0x09, 0x00, 0x01})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestParseSessionKeyWithChecksum_ErrorInvalidPadding(t *testing.T) {
	// Build valid data then corrupt the padding
	sessionKey := make([]byte, 32)
	data := BuildSessionKeyWithChecksum(openpgp.SymAlgoAES256, sessionKey)

	// Corrupt last byte (padding indicator)
	data[len(data)-1] = 0 // invalid: padding value of 0

	_, _, err := ParseSessionKeyWithChecksum(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "padding")
}

func TestParseSessionKeyWithChecksum_ErrorChecksumMismatch(t *testing.T) {
	sessionKey := make([]byte, 32)
	_, err := rand.Read(sessionKey)
	require.NoError(t, err)

	data := BuildSessionKeyWithChecksum(openpgp.SymAlgoAES256, sessionKey)

	// Corrupt a byte in the session key area (before padding)
	// data layout: algo(1) || key(32) || checksum(2) || padding
	// Flip a bit in the key area to cause checksum mismatch
	data[1] ^= 0xFF

	_, _, err = ParseSessionKeyWithChecksum(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "checksum mismatch")
}

// ─── GenerateSessionKey ────────────────────────────────────────────────────────

func TestGenerateSessionKey_AES128(t *testing.T) {
	key, err := GenerateSessionKey(openpgp.SymAlgoAES128)
	require.NoError(t, err)
	assert.Len(t, key, 16)
}

func TestGenerateSessionKey_AES256(t *testing.T) {
	key, err := GenerateSessionKey(openpgp.SymAlgoAES256)
	require.NoError(t, err)
	assert.Len(t, key, 32)
}

func TestGenerateSessionKey_ErrorUnsupportedAlgo(t *testing.T) {
	_, err := GenerateSessionKey(0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported symmetric algorithm")
}

func TestGenerateSessionKey_Randomness(t *testing.T) {
	// Two generated keys for the same algo should be different
	key1, err := GenerateSessionKey(openpgp.SymAlgoAES256)
	require.NoError(t, err)

	key2, err := GenerateSessionKey(openpgp.SymAlgoAES256)
	require.NoError(t, err)

	assert.NotEqual(t, key1, key2, "consecutive keys should differ (random)")
}

// ─── Curve25519 ECDH ────────────────────────────────────────────────────────────

func TestWrapUnwrapCurve25519_RoundTrip(t *testing.T) {
	// Generate an X25519 key pair
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)

	params := &ECDHParams{
		HashAlgo:  openpgp.HashAlgoSHA256,
		SymAlgo:   openpgp.SymAlgoAES256,
		PublicKey: privateKey.PublicKey().Bytes(), // 32 bytes native
		Curve:     ECDHCurveCurve25519,
	}

	sessionKey := make([]byte, 32)
	_, err = rand.Read(sessionKey)
	require.NoError(t, err)

	fingerprint := make([]byte, 20)
	_, err = rand.Read(fingerprint)
	require.NoError(t, err)

	// Wrap
	ephemeralPoint, wrappedKey, err := WrapSessionKey(params, sessionKey, fingerprint)
	require.NoError(t, err)
	assert.Len(t, ephemeralPoint, 33, "Curve25519 ephemeral point should be 33 bytes (0x40 prefix + 32)")
	assert.Equal(t, byte(0x40), ephemeralPoint[0], "ephemeral point should have 0x40 prefix")
	assert.Greater(t, len(wrappedKey), len(sessionKey), "wrapped key should be larger than session key")

	// Unwrap
	recovered, err := UnwrapSessionKey(params, ephemeralPoint, wrappedKey, privateKey, fingerprint)
	require.NoError(t, err)
	assert.Equal(t, sessionKey, recovered)
}

func TestWrapCurve25519_ErrorInvalidPublicKeyLength(t *testing.T) {
	params := &ECDHParams{
		HashAlgo:  openpgp.HashAlgoSHA256,
		SymAlgo:   openpgp.SymAlgoAES256,
		PublicKey: make([]byte, 33), // wrong length for Curve25519
		Curve:     ECDHCurveCurve25519,
	}

	_, _, err := WrapSessionKey(params, make([]byte, 32), make([]byte, 20))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid Curve25519 public key length")
}

func TestUnwrapCurve25519_ErrorInvalidEphemeralPrefix(t *testing.T) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)

	params := &ECDHParams{
		HashAlgo:  openpgp.HashAlgoSHA256,
		SymAlgo:   openpgp.SymAlgoAES256,
		PublicKey: privateKey.PublicKey().Bytes(),
		Curve:     ECDHCurveCurve25519,
	}

	badEphemeral := make([]byte, 33)
	badEphemeral[0] = 0x04 // wrong prefix

	_, err = UnwrapSessionKey(params, badEphemeral, make([]byte, 24), privateKey, make([]byte, 20))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "0x40 prefix")
}

func TestWrapCurve25519_RegressionPrivateKeyAsPublicKey(t *testing.T) {
	// Regression test: iOS bug returned privateKey.rawRepresentation (the private
	// scalar) instead of privateKey.publicKey.rawRepresentation (the public
	// u-coordinate). Both are 32 bytes, so the CLI accepted it and encrypted to the
	// wrong key. This test verifies that encrypting to the private scalar bytes
	// produces ciphertext that cannot be unwrapped with the real private key.

	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)

	sessionKey := make([]byte, 32)
	_, err = rand.Read(sessionKey)
	require.NoError(t, err)

	fingerprint := make([]byte, 20)
	_, err = rand.Read(fingerprint)
	require.NoError(t, err)

	// Simulate the bug: use private key bytes as the "public key"
	buggyParams := &ECDHParams{
		HashAlgo:  openpgp.HashAlgoSHA256,
		SymAlgo:   openpgp.SymAlgoAES256,
		PublicKey: privateKey.Bytes(), // BUG: private scalar, not public key
		Curve:     ECDHCurveCurve25519,
	}

	ephemeralPoint, wrappedKey, err := WrapSessionKey(buggyParams, sessionKey, fingerprint)
	require.NoError(t, err, "wrapping should succeed (CLI can't distinguish 32-byte scalar from public key)")

	// Attempt to unwrap with the real private key — should fail because the shared
	// secrets differ (CLI encrypted to scalar_mult(ephemeral, private_scalar) instead
	// of scalar_mult(ephemeral, public_u_coordinate))
	_, err = UnwrapSessionKey(buggyParams, ephemeralPoint, wrappedKey, privateKey, fingerprint)
	assert.Error(t, err, "unwrap must fail when encrypted to private key bytes instead of public key")
	assert.Contains(t, err.Error(), "IV mismatch", "should fail with AES key unwrap IV mismatch")

	// Now verify the correct path works
	correctParams := &ECDHParams{
		HashAlgo:  openpgp.HashAlgoSHA256,
		SymAlgo:   openpgp.SymAlgoAES256,
		PublicKey: privateKey.PublicKey().Bytes(), // Correct: public key
		Curve:     ECDHCurveCurve25519,
	}

	ephemeralPoint, wrappedKey, err = WrapSessionKey(correctParams, sessionKey, fingerprint)
	require.NoError(t, err)

	recovered, err := UnwrapSessionKey(correctParams, ephemeralPoint, wrappedKey, privateKey, fingerprint)
	require.NoError(t, err)
	assert.Equal(t, sessionKey, recovered, "correct public key must round-trip successfully")
}

func TestDeriveKEK_Curve25519OID(t *testing.T) {
	sharedSecret := make([]byte, 32)
	_, err := rand.Read(sharedSecret)
	require.NoError(t, err)

	fingerprint := make([]byte, 20)
	_, err = rand.Read(fingerprint)
	require.NoError(t, err)

	kekP256, err := deriveKEK(sharedSecret, openpgp.HashAlgoSHA256, openpgp.SymAlgoAES256, fingerprint, openpgp.OIDP256)
	require.NoError(t, err)

	kekCurve25519, err := deriveKEK(sharedSecret, openpgp.HashAlgoSHA256, openpgp.SymAlgoAES256, fingerprint, openpgp.OIDCurve25519)
	require.NoError(t, err)

	assert.NotEqual(t, kekP256, kekCurve25519, "different OIDs must produce different KEKs")
	assert.Len(t, kekCurve25519, 32, "AES-256 KEK should be 32 bytes")
}
