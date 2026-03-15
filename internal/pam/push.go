package pam

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"

	"github.com/ackagent/cli/crypto"
	protocol "github.com/ackagent/api/go/protocol"
	"github.com/ackagent/cli/internal/shared/transport"
)

// Push authentication errors.
var (
	ErrNoDevicesForUser = errors.New("no devices available for user")
	ErrInvalidSignature = errors.New("invalid attestation signature")
)

// PushResult represents the result of a push authentication attempt.
type PushResult struct {
	// Approved indicates whether the request was approved.
	Approved bool
	// ApproverId is the UUID of the approver device that approved (if approved).
	ApproverId string
	// AuthPublicKeyHex is the hex-encoded auth public key of the approving device.
	AuthPublicKeyHex string
	// Timestamp is the response timestamp.
	Timestamp int64
}

// PushAuthenticator handles push-based authentication flow.
type PushAuthenticator struct {
	config *Config
	client *Client
	cache  *DeviceKeyCache

	// currentRequestID is stored for attestation verification.
	currentRequestID string
	// currentRequestIDBytes is the binary request ID for key derivation and attestation.
	currentRequestIDBytes []byte
	// ephemeralPrivate is the requester's ephemeral private key for response decryption.
	ephemeralPrivate []byte
}

// NewPushAuthenticator creates a new push authenticator.
func NewPushAuthenticator(config *Config) (*PushAuthenticator, error) {
	client := NewClient(config)

	// Load device key cache if enabled
	var cache *DeviceKeyCache
	if config.Cache.Enabled {
		var err error
		cache, err = LoadDeviceKeyCache(config.Cache.CacheFile)
		if err != nil {
			log.Printf("Warning: failed to load device key cache: %v", err)
			// Continue without cache - will fail later if no devices
		}
	}

	return &PushAuthenticator{
		config: config,
		client: client,
		cache:  cache,
	}, nil
}

// Authenticate performs push authentication for the given context.
func (a *PushAuthenticator) Authenticate(authCtx *AuthContext) (*PushResult, error) {
	return a.AuthenticateWithContext(context.Background(), authCtx)
}

// AuthenticateWithContext performs push authentication with cancellation support.
func (a *PushAuthenticator) AuthenticateWithContext(ctx context.Context, authCtx *AuthContext) (*PushResult, error) {
	// Check for cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	// Step 1: Authenticate with OIDC service via client_credentials grant
	log.Printf("Authenticating service account %s with OIDC service", a.config.Organization.ServiceAccountID)
	if err := a.client.Authenticate(); err != nil {
		return nil, fmt.Errorf("service account authentication failed: %w", err)
	}

	// Step 2: Get the AckAgent email for this user
	ackAgentUser := a.config.GetUserEmail(authCtx.LocalUsername)
	log.Printf("Sending PAM auth request for %s -> %s", authCtx.LocalUsername, ackAgentUser)

	// Step 3: Get device keys from cache
	deviceKeys, err := a.getDeviceKeys(ackAgentUser)
	if err != nil {
		return nil, err
	}
	log.Printf("Found %d device(s) for %s", len(deviceKeys), ackAgentUser)

	// Step 4: Build the PAM auth request
	request := NewPamAuthPayload(authCtx, ackAgentUser)

	// Step 5: Send request to relay with E2E encryption
	requestID, requestIDBytes, ephemeralPrivate, err := a.client.SendPamRequest(
		request,
		a.config.Organization.ServiceAccountID,
		deviceKeys,
		a.config.Auth.Timeout,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to send PAM request: %w", err)
	}
	log.Printf("Request submitted, ID: %s", requestID)
	a.currentRequestID = requestID
	a.currentRequestIDBytes = requestIDBytes
	a.ephemeralPrivate = ephemeralPrivate

	// Step 6: Wait for encrypted response from relay
	log.Printf("Waiting for approval (timeout: %ds)", a.config.Auth.Timeout)
	relayResp, err := a.client.WaitForResponse(
		requestID,
		a.config.Auth.Timeout,
		a.config.Auth.PollIntervalMs,
	)
	if err != nil {
		if errors.Is(err, ErrTimeout) {
			return &PushResult{Approved: false}, nil
		}
		return nil, err
	}

	// Step 7: Verify attestation (if required), decrypt, and process response
	return a.decryptAndProcess(relayResp, ackAgentUser)
}

// getDeviceKeys retrieves device keys for a user from the cache.
func (a *PushAuthenticator) getDeviceKeys(email string) ([]crypto.DeviceKey, error) {
	if a.cache == nil {
		return nil, fmt.Errorf("%w: cache not enabled", ErrNoDevicesForUser)
	}

	cachedDevices := a.cache.GetUserDevices(email)
	if len(cachedDevices) == 0 {
		return nil, fmt.Errorf("%w: %s (not in cache)", ErrNoDevicesForUser, email)
	}

	deviceKeys := make([]crypto.DeviceKey, 0, len(cachedDevices))
	for _, device := range cachedDevices {
		// Decode the P-256 encryption public key from hex
		publicKeyBytes, err := hex.DecodeString(device.EncryptionPublicKeyHex)
		if err != nil {
			log.Printf("Warning: invalid device public key for approverId=%s: %v", device.ApproverId, err)
			continue
		}

		if len(publicKeyBytes) != crypto.PublicKeySize {
			log.Printf("Warning: skipping device approverId=%s: invalid public key size %d (expected %d)",
				device.ApproverId, len(publicKeyBytes), crypto.PublicKeySize)
			continue
		}

		deviceKeys = append(deviceKeys, crypto.DeviceKey{
			EncryptionPublicKeyHex: device.EncryptionPublicKeyHex,
			PublicKey:              publicKeyBytes,
		})
	}

	if len(deviceKeys) == 0 {
		return nil, fmt.Errorf("%w: %s (no valid keys in cache)", ErrNoDevicesForUser, email)
	}

	return deviceKeys, nil
}

// decryptAndProcess decrypts the E2E response and processes the plaintext PAM auth response.
// Attestation is now anonymous (BBS+ proof inside the encrypted blob) rather than
// identified-mode metadata on the relay response.
func (a *PushAuthenticator) decryptAndProcess(relayResp *RelayResponseStatus, ackAgentUser string) (*PushResult, error) {
	// 1. Decrypt the E2E encrypted response
	decrypted, err := transport.DecryptResponse(
		a.ephemeralPrivate,
		relayResp.ApproverEphemeralKey,
		a.currentRequestIDBytes,
		relayResp.ResponseNonce,
		relayResp.EncryptedResponse,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt response: %w", err)
	}

	// 2. Unmarshal plaintext into PamAuthResponse
	var pamResp protocol.PamAuthResponse
	if err := json.Unmarshal(decrypted, &pamResp); err != nil {
		return nil, fmt.Errorf("failed to parse decrypted response: %w", err)
	}

	// 3. Anonymous attestation for PAM is not yet supported.
	// PAM auth responses use a separate protocol type (PamAuthResponse) that does not
	// currently include BBS+ anonymous attestation. This will be added in a future update.
	if a.config.Auth.RequireAttestation {
		log.Printf("Warning: attestation verification requested but PamAuthResponse does not include anonymous attestation yet")
	}

	// 4. Process the decrypted response
	return a.processResponse(&pamResp, ackAgentUser)
}

// processResponse processes the decrypted authentication response.
func (a *PushAuthenticator) processResponse(response *protocol.PamAuthResponse, ackAgentUser string) (*PushResult, error) {
	switch response.Status {
	case protocol.PamAuthResponseStatusApproved:
		authPublicKey := ""
		if response.AuthPublicKeyHex != nil {
			authPublicKey = *response.AuthPublicKeyHex
		}
		log.Printf("Request approved by device (authPublicKey=%s)", authPublicKey)

		var timestamp int64
		if response.Timestamp != nil {
			timestamp = *response.Timestamp
		}

		return &PushResult{
			Approved:         true,
			AuthPublicKeyHex: authPublicKey,
			Timestamp:        timestamp,
		}, nil

	case protocol.PamAuthResponseStatusRejected:
		log.Printf("Request rejected by user")
		return &PushResult{Approved: false}, nil

	default:
		return nil, fmt.Errorf("unexpected response status: %s", response.Status)
	}
}
