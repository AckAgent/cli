package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/ackagent/cli/crypto"
	"github.com/google/uuid"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

type vectors struct {
	RequestID                 string `json:"request_id"`
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
	CiphertextHex             string `json:"ciphertext_hex"`
}

func clampScalar(k []byte) {
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
}

func main() {
	requestID := uuid.MustParse("7c9e6679-7425-40de-944b-e07fc1f90ae7")
	requestIDBytes, _ := requestID.MarshalBinary()

	requesterPriv := make([]byte, 32)
	signerIdentityPriv := make([]byte, 32)
	signerEphemeralPriv := make([]byte, 32)
	for i := 0; i < 32; i++ {
		requesterPriv[i] = byte(i + 1)
		signerIdentityPriv[i] = byte(i + 33)
		signerEphemeralPriv[i] = byte(i + 65)
	}

	clampScalar(requesterPriv)
	clampScalar(signerIdentityPriv)
	clampScalar(signerEphemeralPriv)

	var requesterPub, signerIdentityPub, signerEphemeralPub [32]byte
	var requesterPrivArr, signerIdentityPrivArr, signerEphemeralPrivArr [32]byte
	copy(requesterPrivArr[:], requesterPriv)
	copy(signerIdentityPrivArr[:], signerIdentityPriv)
	copy(signerEphemeralPrivArr[:], signerEphemeralPriv)

	curve25519.ScalarBaseMult(&requesterPub, &requesterPrivArr)
	curve25519.ScalarBaseMult(&signerIdentityPub, &signerIdentityPrivArr)
	curve25519.ScalarBaseMult(&signerEphemeralPub, &signerEphemeralPrivArr)

	requestKey, err := crypto.DeriveRequestKey(requesterPriv, signerIdentityPub[:], requestIDBytes)
	if err != nil {
		panic(err)
	}
	responseKey, err := crypto.DeriveResponseKey(signerEphemeralPriv, requesterPub[:], requestIDBytes)
	if err != nil {
		panic(err)
	}

	plaintext := []byte("hello-ackagent")
	nonce := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}

	aead, err := chacha20poly1305.New(requestKey)
	if err != nil {
		panic(err)
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	out := vectors{
		RequestID:                 requestID.String(),
		RequestIDBytesHex:         hex.EncodeToString(requestIDBytes),
		RequesterEphemeralPrivate: hex.EncodeToString(requesterPriv),
		RequesterEphemeralPublic:  hex.EncodeToString(requesterPub[:]),
		SignerIdentityPrivate:     hex.EncodeToString(signerIdentityPriv),
		SignerIdentityPublic:      hex.EncodeToString(signerIdentityPub[:]),
		SignerEphemeralPrivate:    hex.EncodeToString(signerEphemeralPriv),
		SignerEphemeralPublic:     hex.EncodeToString(signerEphemeralPub[:]),
		RequestKeyHex:             hex.EncodeToString(requestKey),
		ResponseKeyHex:            hex.EncodeToString(responseKey),
		PlaintextHex:              hex.EncodeToString(plaintext),
		NonceHex:                  hex.EncodeToString(nonce),
		CiphertextHex:             hex.EncodeToString(ciphertext),
	}

	encoded, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", encoded)
}
