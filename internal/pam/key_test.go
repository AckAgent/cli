package pam

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateSigningKey(t *testing.T) {
	key, err := GenerateSigningKey()
	require.NoError(t, err)

	// PublicKeyHex should be 128 characters (64 bytes as hex)
	assert.Len(t, key.PublicKeyHex(), 128)
}

func TestSigningKey_Sign(t *testing.T) {
	key, err := GenerateSigningKey()
	require.NoError(t, err)

	data := []byte("test message to sign")
	signature, err := key.Sign(data)
	require.NoError(t, err)
	assert.NotEmpty(t, signature)

	// Verify the signature
	derPubKey, err := key.PublicKeyDER()
	require.NoError(t, err)

	pubKeyIface, err := x509.ParsePKIXPublicKey(derPubKey)
	require.NoError(t, err)
	pubKey := pubKeyIface.(*ecdsa.PublicKey)

	hash := sha256.Sum256(data)
	valid := ecdsa.VerifyASN1(pubKey, hash[:], signature)
	assert.True(t, valid)
}

func TestSigningKey_SignTokenRequest(t *testing.T) {
	key, err := GenerateSigningKey()
	require.NoError(t, err)

	timestamp := int64(1706000000)
	nonce := []byte("0123456789abcdef") // 16 bytes

	signature, err := key.SignTokenRequest(timestamp, nonce)
	require.NoError(t, err)
	assert.NotEmpty(t, signature)

	// The signature should be valid DER-encoded ECDSA
	// We can verify by reconstructing the message
	derPubKey, err := key.PublicKeyDER()
	require.NoError(t, err)

	pubKeyIface, err := x509.ParsePKIXPublicKey(derPubKey)
	require.NoError(t, err)
	pubKey := pubKeyIface.(*ecdsa.PublicKey)

	// Reconstruct message: 8-byte BE timestamp || nonce
	message := make([]byte, 8+len(nonce))
	message[0] = byte(timestamp >> 56)
	message[1] = byte(timestamp >> 48)
	message[2] = byte(timestamp >> 40)
	message[3] = byte(timestamp >> 32)
	message[4] = byte(timestamp >> 24)
	message[5] = byte(timestamp >> 16)
	message[6] = byte(timestamp >> 8)
	message[7] = byte(timestamp)
	copy(message[8:], nonce)

	hash := sha256.Sum256(message)
	valid := ecdsa.VerifyASN1(pubKey, hash[:], signature)
	assert.True(t, valid)
}

func TestSigningKey_ToPEM(t *testing.T) {
	key, err := GenerateSigningKey()
	require.NoError(t, err)

	pemData, err := key.ToPEM()
	require.NoError(t, err)

	// Should be valid PEM
	block, _ := pem.Decode(pemData)
	require.NotNil(t, block)
	assert.Equal(t, "PRIVATE KEY", block.Type)

	// Should be parseable back
	parsedKey, err := ParseSigningKeyPEM(pemData)
	require.NoError(t, err)
	assert.Equal(t, key.PublicKeyHex(), parsedKey.PublicKeyHex())
}

func TestSigningKey_SaveAndLoad(t *testing.T) {
	key, err := GenerateSigningKey()
	require.NoError(t, err)

	// Save to temp file
	tmpFile, err := os.CreateTemp("", "pam-key-*.pem")
	require.NoError(t, err)
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	err = key.SaveToFile(tmpFile.Name())
	require.NoError(t, err)

	// Load from file
	loadedKey, err := LoadSigningKeyUnsafe(tmpFile.Name())
	require.NoError(t, err)
	assert.Equal(t, key.PublicKeyHex(), loadedKey.PublicKeyHex())
}

func TestParseSigningKeyPEM_PKCS8(t *testing.T) {
	// Generate a key and export as PKCS#8
	key, err := GenerateSigningKey()
	require.NoError(t, err)

	pemData, err := key.ToPEM()
	require.NoError(t, err)

	// Parse it back
	parsedKey, err := ParseSigningKeyPEM(pemData)
	require.NoError(t, err)
	assert.Equal(t, key.PublicKeyHex(), parsedKey.PublicKeyHex())
}

func TestParseSigningKeyPEM_Invalid(t *testing.T) {
	tests := []struct {
		name    string
		pem     string
		wantErr error
	}{
		{
			name:    "not PEM",
			pem:     "not a PEM file",
			wantErr: ErrInvalidPEM,
		},
		{
			name: "wrong type",
			pem: `-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA
-----END RSA PRIVATE KEY-----`,
			wantErr: ErrInvalidKeyType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseSigningKeyPEM([]byte(tt.pem))
			require.Error(t, err)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			}
		})
	}
}

func TestLoadSigningKey_NotFound(t *testing.T) {
	_, err := LoadSigningKeyUnsafe("/nonexistent/path/to/key.pem")
	require.Error(t, err)
}

func TestSigningKey_PublicKey(t *testing.T) {
	key, err := GenerateSigningKey()
	require.NoError(t, err)

	pubKey := key.PublicKey()
	require.NotNil(t, pubKey)

	// Should be the same key used for signing
	data := []byte("test data for public key verification")
	sig, err := key.Sign(data)
	require.NoError(t, err)

	hash := sha256.Sum256(data)
	valid := ecdsa.VerifyASN1(pubKey, hash[:], sig)
	assert.True(t, valid, "PublicKey() should return the matching public key")
}

func TestParseSigningKeyPEM_ECPrivateKey(t *testing.T) {
	// Generate a key and export as SEC 1 / EC PRIVATE KEY format
	key, err := GenerateSigningKey()
	require.NoError(t, err)

	ecDer, err := x509.MarshalECPrivateKey(key.privateKey)
	require.NoError(t, err)

	ecPem := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: ecDer,
	})

	parsed, err := ParseSigningKeyPEM(ecPem)
	require.NoError(t, err)
	assert.Equal(t, key.PublicKeyHex(), parsed.PublicKeyHex())
}

func TestSigningKey_SaveToFile_Permissions(t *testing.T) {
	key, err := GenerateSigningKey()
	require.NoError(t, err)

	tmpDir := t.TempDir()
	path := tmpDir + "/signing-key.pem"

	err = key.SaveToFile(path)
	require.NoError(t, err)

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm(), "key file should have 0600 permissions")
}

func TestSigningKey_PublicKeyDER_Parseable(t *testing.T) {
	key, err := GenerateSigningKey()
	require.NoError(t, err)

	der, err := key.PublicKeyDER()
	require.NoError(t, err)

	pubIface, err := x509.ParsePKIXPublicKey(der)
	require.NoError(t, err)

	pubKey, ok := pubIface.(*ecdsa.PublicKey)
	require.True(t, ok, "parsed key should be ECDSA")
	assert.Equal(t, key.PublicKey().X, pubKey.X)
	assert.Equal(t, key.PublicKey().Y, pubKey.Y)
}

func TestLoadSigningKey_PathTraversal(t *testing.T) {
	// LoadSigningKey should reject paths with ".."
	_, err := LoadSigningKey("/etc/../etc/shadow")
	require.Error(t, err)
}

func TestSigningKey_RoundtripPKCS8(t *testing.T) {
	// Generate, export to PEM, parse back, verify signing works
	key, err := GenerateSigningKey()
	require.NoError(t, err)

	pemData, err := key.ToPEM()
	require.NoError(t, err)

	loaded, err := ParseSigningKeyPEM(pemData)
	require.NoError(t, err)

	// Sign with loaded key and verify with original key's public key
	data := []byte("roundtrip test data")
	sig, err := loaded.Sign(data)
	require.NoError(t, err)

	hash := sha256.Sum256(data)
	valid := ecdsa.VerifyASN1(key.PublicKey(), hash[:], sig)
	assert.True(t, valid, "signature from loaded key should verify with original public key")
}
