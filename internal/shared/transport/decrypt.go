package transport

import (
	"fmt"

	"github.com/ackagent/cli/crypto"
)

// DecryptResponse decrypts an E2E encrypted response from the signer.
//
// Parameters:
//   - ephemeralPrivate: The requester's ephemeral private key (32 bytes)
//   - signerPublic: The signer's ephemeral public key from the response (32 bytes)
//   - requestID: The request ID used for key derivation (16 bytes)
//   - nonce: The encryption nonce from the response (12 bytes)
//   - ciphertext: The encrypted response payload
//
// Returns the decrypted response bytes, which can then be unmarshaled
// into the appropriate response type by the caller.
func DecryptResponse(
	ephemeralPrivate []byte,
	signerPublic []byte,
	requestID []byte,
	nonce []byte,
	ciphertext []byte,
) ([]byte, error) {
	// Validate signer's ephemeral public key
	if len(signerPublic) != crypto.PublicKeySize {
		return nil, fmt.Errorf("invalid signer ephemeral public key size: got %d, want %d", len(signerPublic), crypto.PublicKeySize)
	}

	// Validate we have encrypted data
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("no encrypted response data")
	}

	// Derive response decryption key: ECDH(our_ephemeral_private, signer_ephemeral_public)
	responseKey, err := crypto.DeriveResponseKey(ephemeralPrivate, signerPublic, requestID)
	if err != nil {
		return nil, fmt.Errorf("failed to derive response key: %w", err)
	}

	// Decrypt response (request ID as AAD binds response to this request)
	decrypted, err := crypto.Decrypt(responseKey, nonce, ciphertext, requestID)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return decrypted, nil
}

// DecryptResponseFromStatus is a convenience function that decrypts a response
// using fields from a Response struct.
func (r *Response) Decrypt(ephemeralPrivate []byte, requestID []byte) ([]byte, error) {
	return DecryptResponse(
		ephemeralPrivate,
		r.EphemeralPublic,
		requestID,
		r.ResponseNonce,
		r.EncryptedResponse,
	)
}
