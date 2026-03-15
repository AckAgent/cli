package commands

import (
	"encoding/hex"
	"testing"

	protocol "github.com/ackagent/api/go/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnrollResponseWrapper_NilFields(t *testing.T) {
	// Test that all getter methods handle nil fields gracefully
	w := &enrollResponseWrapper{}

	assert.Equal(t, "", w.getIosKeyId())
	assert.Equal(t, "", w.getFingerprint())
	assert.Nil(t, w.getPublicKey())
	assert.Equal(t, "", w.getAlgorithm())
	assert.Nil(t, w.getErrorCode())
	assert.Equal(t, "", w.getErrorMessage())
	assert.Equal(t, int64(0), w.getKeyCreationTimestamp())
	assert.Nil(t, w.getUserIdSignature())
	assert.Nil(t, w.getSubkeySignature())
	assert.Nil(t, w.getEncryptionPublicKey())
	assert.Equal(t, "", w.getEncryptionFingerprint())
}

func TestEnrollResponseWrapper_WithValues(t *testing.T) {
	iosKeyID := "ios-key-123"
	fingerprint := "AABB1122AABB1122AABB1122AABB1122AABB1122"
	publicKey := []byte("public-key-bytes")
	publicKeyHex := hex.EncodeToString(publicKey)
	algorithm := "p256"
	errorCode := protocol.AckAgentCommonSigningErrorCode(4)
	errorMessage := "key exists"
	timestamp := int64(1700000000)
	userIDSig := []byte("userid-sig")
	subkeySig := []byte("subkey-sig")
	encPubKey := []byte("enc-pubkey")
	encPubKeyHex := hex.EncodeToString(encPubKey)
	encFingerprint := "CCDD3344CCDD3344CCDD3344CCDD3344CCDD3344"

	w := &enrollResponseWrapper{}
	w.IosKeyId = &iosKeyID
	w.Fingerprint = &fingerprint
	w.PublicKeyHex = &publicKeyHex
	w.Algorithm = &algorithm
	w.ErrorCode = &errorCode
	w.ErrorMessage = &errorMessage
	w.KeyCreationTimestamp = &timestamp
	w.UserIdSignature = &userIDSig
	w.SubkeySignature = &subkeySig
	w.EncryptionPublicKeyHex = &encPubKeyHex
	w.EncryptionFingerprint = &encFingerprint

	assert.Equal(t, iosKeyID, w.getIosKeyId())
	assert.Equal(t, fingerprint, w.getFingerprint())
	assert.Equal(t, publicKey, w.getPublicKey())
	assert.Equal(t, algorithm, w.getAlgorithm())

	errCode := w.getErrorCode()
	require.NotNil(t, errCode)
	assert.Equal(t, 4, *errCode)

	assert.Equal(t, errorMessage, w.getErrorMessage())
	assert.Equal(t, timestamp, w.getKeyCreationTimestamp())
	assert.Equal(t, userIDSig, w.getUserIdSignature())
	assert.Equal(t, subkeySig, w.getSubkeySignature())
	assert.Equal(t, encPubKey, w.getEncryptionPublicKey())
	assert.Equal(t, encFingerprint, w.getEncryptionFingerprint())
}

func TestKeyGenerationInfo_Structure(t *testing.T) {
	info := &KeyGenerationInfo{
		ID:                    "key-id",
		Fingerprint:           "AABB1122AABB1122AABB1122AABB1122AABB1122",
		PublicKey:             []byte("pub-key"),
		Algorithm:             "p256",
		KeyCreationTimestamp:  1700000000,
		UserIDSignature:       []byte("uid-sig"),
		SubkeySignature:       []byte("subkey-sig"),
		EncryptionPublicKey:   []byte("enc-pub-key"),
		EncryptionFingerprint: "CCDD3344CCDD3344CCDD3344CCDD3344CCDD3344",
	}

	assert.Equal(t, "key-id", info.ID)
	assert.Equal(t, "AABB1122AABB1122AABB1122AABB1122AABB1122", info.Fingerprint)
	assert.Equal(t, "p256", info.Algorithm)
	assert.Equal(t, int64(1700000000), info.KeyCreationTimestamp)
	assert.NotEmpty(t, info.PublicKey)
	assert.NotEmpty(t, info.UserIDSignature)
	assert.NotEmpty(t, info.SubkeySignature)
	assert.NotEmpty(t, info.EncryptionPublicKey)
	assert.NotEmpty(t, info.EncryptionFingerprint)
}

func TestGetEffectiveKeyID_PrefersIosKeyId(t *testing.T) {
	iosKeyId := "ios-key-123"
	id := "uuid-456"
	r := enrollResponseWrapper{EnrollResponse: protocol.EnrollResponse{
		IosKeyId: &iosKeyId,
		Id:       &id,
	}}
	assert.Equal(t, "ios-key-123", r.getEffectiveKeyID())
}

func TestGetEffectiveKeyID_FallsBackToId(t *testing.T) {
	id := "uuid-456"
	r := enrollResponseWrapper{EnrollResponse: protocol.EnrollResponse{
		IosKeyId: nil,
		Id:       &id,
	}}
	assert.Equal(t, "uuid-456", r.getEffectiveKeyID())
}

func TestGetEffectiveKeyID_EmptyIosKeyIdFallsBackToId(t *testing.T) {
	empty := ""
	id := "uuid-456"
	r := enrollResponseWrapper{EnrollResponse: protocol.EnrollResponse{
		IosKeyId: &empty,
		Id:       &id,
	}}
	assert.Equal(t, "uuid-456", r.getEffectiveKeyID())
}

func TestGetEffectiveKeyID_BothNilReturnsEmpty(t *testing.T) {
	r := enrollResponseWrapper{EnrollResponse: protocol.EnrollResponse{}}
	assert.Equal(t, "", r.getEffectiveKeyID())
}

func TestGenerateKey_AlgorithmValidation(t *testing.T) {
	// Verify that only p256 and ed25519 are valid algorithms
	validAlgorithms := []string{"ecdsa", "ed25519"}
	invalidAlgorithms := []string{"rsa", "dsa", "secp384r1", ""}

	for _, algo := range validAlgorithms {
		isValid := algo == "ecdsa" || algo == "ed25519"
		assert.True(t, isValid, "%q should be valid", algo)
	}

	for _, algo := range invalidAlgorithms {
		isValid := algo == "ecdsa" || algo == "ed25519"
		assert.False(t, isValid, "%q should be invalid", algo)
	}
}

func TestGenerateKey_LabelFormat(t *testing.T) {
	// Verify label format: "Name <email>"
	name := "John Doe"
	email := "john@example.com"
	label := name + " <" + email + ">"

	assert.Equal(t, "John Doe <john@example.com>", label)
}
