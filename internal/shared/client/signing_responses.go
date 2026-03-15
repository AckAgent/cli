package client

import (
	"fmt"

	protocol "github.com/ackagent/api/go/protocol"
)

// signingError converts an error code and message into a descriptive error.
// The noun parameter describes the request type (e.g., "signing", "decryption").
// Returns nil if errCode is nil (caller should handle no-code case).
func signingError(errCode *int, errMsg, noun string) error {
	if errCode == nil {
		return nil
	}
	code := protocol.AckAgentCommonSigningErrorCode(*errCode)
	switch code {
	case protocol.N1: // rejected
		return fmt.Errorf("%s request rejected: %s", noun, errMsg)
	case protocol.N2: // expired
		return ErrExpired
	case protocol.N3: // unsupported algorithm
		return fmt.Errorf("unsupported algorithm: %s", errMsg)
	case protocol.N4: // invalid requester
		return fmt.Errorf("invalid requester: %s", errMsg)
	case protocol.N5: // key not found
		return fmt.Errorf("key not found: %s", errMsg)
	case protocol.N6: // internal error
		return fmt.Errorf("internal error: %s", errMsg)
	default:
		return fmt.Errorf("unknown error (code %d): %s", *errCode, errMsg)
	}
}

// getErrorCode converts a generated error code pointer to *int.
func getErrorCode(code *protocol.AckAgentCommonSigningErrorCode) *int {
	if code == nil {
		return nil
	}
	c := int(*code)
	return &c
}

// getErrorMessage dereferences a string pointer, returning "" for nil.
func getErrorMessage(msg *string) string {
	if msg == nil {
		return ""
	}
	return *msg
}

// SigningResponse wraps the generated protocol.SignatureResponse with helper methods.
type SigningResponse struct {
	protocol.SignatureResponse
}

// IsSuccess returns true if the response contains a signature
func (r *SigningResponse) IsSuccess() bool {
	return r.ErrorCode == nil && r.Signature != nil && len(*r.Signature) > 0
}

// GetSignature returns the signature bytes, or nil if not present.
func (r *SigningResponse) GetSignature() []byte {
	if r.Signature == nil {
		return nil
	}
	return *r.Signature
}

// GetErrorCode returns the error code as int, or nil if not present.
func (r *SigningResponse) GetErrorCode() *int { return getErrorCode(r.ErrorCode) }

// GetErrorMessage returns the error message, or empty string if not present.
func (r *SigningResponse) GetErrorMessage() string { return getErrorMessage(r.ErrorMessage) }

// Error returns an error for unsuccessful responses
func (r *SigningResponse) Error() error {
	if r.IsSuccess() {
		return nil
	}
	if err := signingError(r.GetErrorCode(), r.GetErrorMessage(), "signing"); err != nil {
		return err
	}
	return ErrRejected
}

// GPGSignResponse wraps the generated protocol.GpgSignatureResponse with helper methods.
type GPGSignResponse struct {
	protocol.GpgSignatureResponse
}

// IsSuccess returns true if the response contains an armored signature
func (r *GPGSignResponse) IsSuccess() bool {
	return r.ErrorCode == nil && r.ArmoredSignature != nil && *r.ArmoredSignature != ""
}

// GetArmoredSignature returns the armored signature, or empty string if not present.
func (r *GPGSignResponse) GetArmoredSignature() string {
	if r.ArmoredSignature == nil {
		return ""
	}
	return *r.ArmoredSignature
}

// GetErrorCode returns the error code as int, or nil if not present.
func (r *GPGSignResponse) GetErrorCode() *int { return getErrorCode(r.ErrorCode) }

// GetErrorMessage returns the error message, or empty string if not present.
func (r *GPGSignResponse) GetErrorMessage() string { return getErrorMessage(r.ErrorMessage) }

// Error returns an error for unsuccessful responses
func (r *GPGSignResponse) Error() error {
	if r.IsSuccess() {
		return nil
	}
	if err := signingError(r.GetErrorCode(), r.GetErrorMessage(), "signing"); err != nil {
		return err
	}
	return ErrRejected
}

// GPGDecryptResponse wraps the generated protocol.GpgDecryptResponse with helper methods.
type GPGDecryptResponse struct {
	protocol.GpgDecryptResponse
}

// IsSuccess returns true if the response contains a session key
func (r *GPGDecryptResponse) IsSuccess() bool {
	return r.ErrorCode == nil && r.SessionKey != nil && len(*r.SessionKey) > 0
}

// GetSessionKey returns the session key bytes, or nil if not present.
func (r *GPGDecryptResponse) GetSessionKey() []byte {
	if r.SessionKey == nil {
		return nil
	}
	return *r.SessionKey
}

// GetAlgorithm returns the algorithm byte, or 0 if not present.
func (r *GPGDecryptResponse) GetAlgorithm() byte {
	if r.Algorithm == nil {
		return 0
	}
	return byte(*r.Algorithm)
}

// GetErrorCode returns the error code as int, or nil if not present.
func (r *GPGDecryptResponse) GetErrorCode() *int { return getErrorCode(r.ErrorCode) }

// GetErrorMessage returns the error message, or empty string if not present.
func (r *GPGDecryptResponse) GetErrorMessage() string { return getErrorMessage(r.ErrorMessage) }

// Error returns an error for unsuccessful responses
func (r *GPGDecryptResponse) Error() error {
	if r.IsSuccess() {
		return nil
	}
	if err := signingError(r.GetErrorCode(), r.GetErrorMessage(), "decryption"); err != nil {
		return err
	}
	return ErrRejected
}
