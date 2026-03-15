// Package transport provides a pluggable transport layer for sending signing requests.
// This allows the CLI to use different communication channels (relay or direct transports)
// while keeping the same E2E encryption and protocol semantics.
package transport

import (
	"context"
	"time"

	relayapi "github.com/ackagent/api/go/relay"
)

// Request represents a signing request to be sent via a transport.
type Request struct {
	// ID is the unique request identifier (UUID)
	ID string

	// RequesterID identifies the requester for routing
	RequesterID string

	// KeyID is the optional specific key to use for signing
	KeyID string

	// SigningPublicKey is the optional hex-encoded public key of the key to use for signing
	SigningPublicKey string

	// EphemeralPublic is the requester's ephemeral P-256 public key (33 bytes, compressed SEC1)
	EphemeralPublic []byte

	// EncryptedPayload is the E2E encrypted request payload
	EncryptedPayload []byte

	// PayloadNonce is the nonce used for encryption
	PayloadNonce []byte

	// WrappedKeys contains per-approver wrapped keys (multi-device mode)
	WrappedKeys []relayapi.WrappedKey

	// ExpiresIn is the request validity duration in seconds
	ExpiresIn int

	// Timestamp is when the request was created (Unix milliseconds)
	Timestamp int64
}

// Response represents a signing response received via a transport.
type Response struct {
	// ID is the request ID this response is for
	ID string

	// Status is the response status: "pending", "responded", "expired"
	// Note: Backend never reveals "approved"/"rejected" - that's in the encrypted response
	Status string

	// EphemeralPublic is the signer's ephemeral public key for response decryption
	EphemeralPublic []byte

	// EncryptedResponse is the E2E encrypted response payload
	EncryptedResponse []byte

	// ResponseNonce is the nonce used for response encryption
	ResponseNonce []byte

	// RespondedAt is when the response was received
	RespondedAt time.Time

	// ExpiresAt is when the request expires
	ExpiresAt time.Time
}

// Transport defines the interface for sending signing requests.
// Different implementations can use HTTP relay or other direct transports.
type Transport interface {
	// Name returns a human-readable name for this transport (e.g., "relay", "bluetooth")
	Name() string

	// Priority returns the transport priority (lower = higher priority, tried first)
	// Recommended values: 1-10 for direct transports, 50+ for relay
	Priority() int

	// IsAvailable checks if this transport can currently be used.
	// For direct transports, this might probe nearby devices.
	// Returns error if availability cannot be determined.
	IsAvailable(ctx context.Context) (bool, error)

	// Send sends a signing request and waits for a response.
	// The timeout parameter limits the total wait time for a response.
	// Returns Response when signer responds, or error on failure/timeout.
	Send(ctx context.Context, req *Request, timeout time.Duration) (*Response, error)
}

// TransportError represents an error from a specific transport.
type TransportError struct {
	Transport string
	Err       error
}

func (e *TransportError) Error() string {
	return e.Transport + ": " + e.Err.Error()
}

func (e *TransportError) Unwrap() error {
	return e.Err
}
