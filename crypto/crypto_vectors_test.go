package crypto

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type encryptionVectors struct {
	RequestIDBytesHex         string `json:"request_id_bytes_hex"`
	RequesterEphemeralPrivate string `json:"requester_ephemeral_private_hex"`
	RequesterEphemeralPublic  string `json:"requester_ephemeral_public_hex"`
	SignerIdentityPrivate     string `json:"signer_identity_private_hex"`
	SignerIdentityPublic      string `json:"signer_identity_public_hex"`
	SignerEphemeralPrivate    string `json:"signer_ephemeral_private_hex"`
	SignerEphemeralPublic     string `json:"signer_ephemeral_public_hex"`
	RequestKeyHex             string `json:"request_key_hex"`
	ResponseKeyHex            string `json:"response_key_hex"`
	PlaintextHex              string `json:"plaintext_hex"`
	NonceHex                  string `json:"nonce_hex"`
	AADHex                    string `json:"aad_hex"`
	CiphertextHex             string `json:"ciphertext_hex"`
}

type testVectors struct {
	EncryptionVectors encryptionVectors `json:"encryption_vectors"`
}

func loadVectors(t *testing.T) testVectors {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), ".."))
	path := filepath.Join(root, "data", "crypto_test_vectors.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read vectors: %v", err)
	}
	var v testVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("failed to parse vectors: %v", err)
	}
	return v
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("invalid hex: %v", err)
	}
	return b
}

func TestCrossLanguageVectors(t *testing.T) {
	vectors := loadVectors(t)
	v := vectors.EncryptionVectors

	requestIDBytes := mustHex(t, v.RequestIDBytesHex)
	requesterPriv := mustHex(t, v.RequesterEphemeralPrivate)
	signerEphemeralPriv := mustHex(t, v.SignerEphemeralPrivate)

	// Test vectors store uncompressed public keys; compress for current API
	requesterPub, err := CompressPublicKey(mustHex(t, v.RequesterEphemeralPublic))
	if err != nil {
		t.Fatalf("compress requester pub: %v", err)
	}
	signerIdentityPub, err := CompressPublicKey(mustHex(t, v.SignerIdentityPublic))
	if err != nil {
		t.Fatalf("compress signer identity pub: %v", err)
	}

	requestKey, err := DeriveRequestKey(requesterPriv, signerIdentityPub, requestIDBytes)
	if err != nil {
		t.Fatalf("derive request key: %v", err)
	}
	if hex.EncodeToString(requestKey) != v.RequestKeyHex {
		t.Fatalf("request key mismatch")
	}

	responseKey, err := DeriveResponseKey(signerEphemeralPriv, requesterPub, requestIDBytes)
	if err != nil {
		t.Fatalf("derive response key: %v", err)
	}
	if hex.EncodeToString(responseKey) != v.ResponseKeyHex {
		t.Fatalf("response key mismatch")
	}

	nonce := mustHex(t, v.NonceHex)
	ciphertext := mustHex(t, v.CiphertextHex)
	plaintext := mustHex(t, v.PlaintextHex)
	aad := mustHex(t, v.AADHex)

	decrypted, err := Decrypt(requestKey, nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if hex.EncodeToString(decrypted) != hex.EncodeToString(plaintext) {
		t.Fatalf("plaintext mismatch")
	}
}
