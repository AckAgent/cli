package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/ackagent/cli/crypto"
	"github.com/ackagent/cli/internal/shared/config"
	"github.com/ackagent/cli/internal/shared/multidevice"
)

// RequestResult contains the response and decryption context from a request.
type RequestResult struct {
	// Response is the transport response
	Response *Response

	// EphemeralPrivate is the requester's ephemeral private key for response decryption
	EphemeralPrivate []byte

	// RequestID is the request ID bytes for key derivation
	RequestID []byte

	// RequestIDString is the string form of the request ID (used as BBS+ pseudonym scope)
	RequestIDString string

	// IssuerKeys holds issuer public keys for BBS+ proof verification.
	// Loaded from config (cached from credential-issuer service).
	IssuerKeys []IssuerKeyInfo

	// SkipAttestationVerify disables attestation verification
	SkipAttestationVerify bool
}

// Decrypt decrypts the response payload and verifies anonymous attestation.
// The BBS+ proof travels inside the encrypted blob, so verification happens after decryption.
func (r *RequestResult) Decrypt() ([]byte, error) {
	decrypted, err := r.DecryptWithoutAttestation()
	if err != nil {
		return nil, err
	}

	if err := VerifyAttestationFromJSON(decrypted, r.RequestIDString, r.IssuerKeys, r.SkipAttestationVerify); err != nil {
		return nil, err
	}

	return decrypted, nil
}

// DecryptWithoutAttestation decrypts the response payload but does not verify BBS+ attestation.
// This is used by enrollment flows, which rely on key-level attestation instead.
func (r *RequestResult) DecryptWithoutAttestation() ([]byte, error) {
	return DecryptResponse(
		r.EphemeralPrivate,
		r.Response.EphemeralPublic,
		r.RequestID,
		r.Response.ResponseNonce,
		r.Response.EncryptedResponse,
	)
}

// RequestBuilder provides a fluent API for building and sending signing requests.
// It handles the common boilerplate: access token retrieval, ephemeral key generation,
// multi-device encryption, and request submission.
type RequestBuilder struct {
	cfg              *config.Config
	managerConfig    ManagerConfig
	keyID            string
	signingPublicKey string
	expiresIn        int
	timestamp        int64
	timeout          time.Duration

	skipAttestationVerify bool

	// err captures any error during building
	err error
}

// NewRequestBuilder creates a new request builder for the given config.
// The builder will validate that the user is logged in.
func NewRequestBuilder(cfg *config.Config) *RequestBuilder {
	b := &RequestBuilder{
		cfg: cfg,
		managerConfig: ManagerConfig{
			EnableBLETransport: cfg.BLEEnabled,
			BLEDevice:          cfg.BLEDevice,
		},
		expiresIn: 120, // Default 2 minutes
		timeout:   config.DefaultSigningTimeout,
	}

	if SkipAttestationRequested() {
		b.skipAttestationVerify = true
	}

	if !cfg.IsLoggedIn() {
		b.err = fmt.Errorf("not logged in: please run 'ackagent login' first")
	}

	return b
}

// WithKey sets the target key for the request.
// signingPublicKey is the hex-encoded public key of the key to use for signing.
func (b *RequestBuilder) WithKey(keyID, signingPublicKey string) *RequestBuilder {
	if b.err != nil {
		return b
	}
	b.keyID = keyID
	b.signingPublicKey = signingPublicKey
	return b
}

// WithExpiration sets the request expiration time in seconds.
func (b *RequestBuilder) WithExpiration(seconds int) *RequestBuilder {
	if b.err != nil {
		return b
	}
	b.expiresIn = seconds
	return b
}

// WithTimeout sets the timeout for waiting for a response.
func (b *RequestBuilder) WithTimeout(timeout time.Duration) *RequestBuilder {
	if b.err != nil {
		return b
	}
	b.timeout = timeout
	return b
}

// WithTimestamp sets the request timestamp (Unix milliseconds).
// If not set, uses current time.
func (b *RequestBuilder) WithTimestamp(ts int64) *RequestBuilder {
	if b.err != nil {
		return b
	}
	b.timestamp = ts
	return b
}

// WithManagerConfig sets the transport manager configuration (e.g., BLE settings).
func (b *RequestBuilder) WithManagerConfig(cfg ManagerConfig) *RequestBuilder {
	b.managerConfig = cfg
	return b
}

// Send encrypts the payload and sends the request, waiting for a response.
// Returns a RequestResult that can be used to decrypt the response.
func (b *RequestBuilder) Send(ctx context.Context, payload any) (*RequestResult, error) {
	if b.err != nil {
		return nil, b.err
	}

	// Get access token
	accessToken, err := b.cfg.GetValidAccessToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get access token: %w", err)
	}

	// Generate ephemeral keypair for forward secrecy
	ephemeral, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	// Generate request ID
	requestID := uuid.New()
	requestIDBytes, err := requestID.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to encode request ID: %w", err)
	}

	// Marshal payload
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Multi-device encryption
	encrypted, err := multidevice.EncryptForDevices(b.cfg, payloadBytes, requestID)
	if err != nil {
		return nil, err
	}

	// Set timestamp if not provided
	timestamp := b.timestamp
	if timestamp == 0 {
		timestamp = time.Now().UnixMilli()
	}

	// Build request
	req := &Request{
		ID:               requestID.String(),
		RequesterID:      b.cfg.UserAccount().RequesterID,
		KeyID:            b.keyID,
		SigningPublicKey: b.signingPublicKey,
		EphemeralPublic:  ephemeral.PublicKey[:],
		EncryptedPayload: encrypted.EncryptedPayload,
		PayloadNonce:     encrypted.PayloadNonce,
		WrappedKeys:      encrypted.WrappedKeys,
		ExpiresIn:        b.expiresIn,
		Timestamp:        timestamp,
	}

	// Send and wait for response
	m := NewManagerWithConfig(b.cfg, accessToken, b.managerConfig)
	resp, err := m.Send(ctx, req, b.timeout)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	// Get issuer public keys from config for BBS+ proof verification
	var issuerKeys []IssuerKeyInfo
	if profile, profileErr := b.cfg.GetActiveProfile(); profileErr == nil {
		if len(profile.IssuerPublicKey) > 0 {
			issuerKeys = []IssuerKeyInfo{{
				ID:        profile.IssuerPublicKeyID,
				PublicKey: profile.IssuerPublicKey,
			}}
		}
	}

	return &RequestResult{
		Response:              resp,
		EphemeralPrivate:      ephemeral.PrivateKey[:],
		RequestID:             requestIDBytes,
		RequestIDString:       requestID.String(),
		IssuerKeys:            issuerKeys,
		SkipAttestationVerify: b.skipAttestationVerify,
	}, nil
}

// SendAndDecrypt sends the request and decrypts the response in one step.
// Returns the decrypted response bytes.
func (b *RequestBuilder) SendAndDecrypt(ctx context.Context, payload any) ([]byte, error) {
	result, err := b.Send(ctx, payload)
	if err != nil {
		return nil, err
	}

	// Check response status
	switch result.Response.Status {
	case "expired":
		return nil, fmt.Errorf("request expired")
	case "responded":
		// Continue to decrypt
	default:
		return nil, fmt.Errorf("unexpected status: %s", result.Response.Status)
	}

	return result.Decrypt()
}
