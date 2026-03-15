package transport

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	relayapi "github.com/ackagent/api/go/relay"
	"github.com/ackagent/cli/internal/shared/client"
)

// RelayTransport implements Transport using the HTTP relay server.
type RelayTransport struct {
	relayURL    string
	deviceID    string
	accessToken string
	pollConfig  client.PollConfig
}

// NewRelayTransport creates a new relay transport.
func NewRelayTransport(relayURL, deviceID string) *RelayTransport {
	return &RelayTransport{
		relayURL:   relayURL,
		deviceID:   deviceID,
		pollConfig: client.DefaultPollConfig(),
	}
}

// SetAccessToken sets the OIDC access token for authenticated requests.
func (t *RelayTransport) SetAccessToken(token string) {
	t.accessToken = token
}

// SetPollConfig sets the polling configuration.
func (t *RelayTransport) SetPollConfig(cfg client.PollConfig) {
	t.pollConfig = cfg
}

// Name returns the transport name.
func (t *RelayTransport) Name() string {
	return "relay"
}

// Priority returns the transport priority.
// Relay has lower priority (50) so direct transports can be tried first when registered.
func (t *RelayTransport) Priority() int {
	return 50
}

// IsAvailable checks if the relay server is reachable.
// For the relay transport, we assume it's always available since network
// errors will be handled during Send.
func (t *RelayTransport) IsAvailable(ctx context.Context) (bool, error) {
	// Relay is always considered available - errors handled at send time
	return true, nil
}

// Send sends a signing request via the relay server.
func (t *RelayTransport) Send(ctx context.Context, req *Request, timeout time.Duration) (*Response, error) {
	// Create client for this request
	httpClient, err := client.NewClient(t.relayURL, t.deviceID)
	if err != nil {
		return nil, fmt.Errorf("failed to create relay client: %w", err)
	}
	if t.accessToken != "" {
		httpClient.SetAccessToken(t.accessToken)
	}

	// Construct the relay API request directly
	apiReq := &relayapi.CreateSigningRequest{
		Id:                       req.ID,
		RequesterId:              req.RequesterID,
		RequesterEphemeralKeyHex: hex.EncodeToString(req.EphemeralPublic),
		EncryptedPayload:         req.EncryptedPayload,
		PayloadNonce:             req.PayloadNonce,
		Timestamp:                req.Timestamp,
	}
	if req.SigningPublicKey != "" {
		apiReq.SigningPublicKeyHex = &req.SigningPublicKey
	}
	if req.ExpiresIn > 0 {
		expiresIn := int32(req.ExpiresIn)
		apiReq.ExpiresIn = &expiresIn
	}
	if len(req.WrappedKeys) > 0 {
		apiReq.WrappedKeys = &req.WrappedKeys
	}

	// Create the signing request
	tlog.Debug("relay: creating signing request id=%s", req.ID)
	createResp, err := httpClient.CreateSigningRequest(ctx, apiReq)
	if err != nil {
		return nil, err
	}

	// Poll for response
	tlog.Debug("relay: polling for response id=%s timeout=%v", req.ID, timeout)
	status, err := httpClient.PollForResponse(ctx, createResp.GetID(), timeout, t.pollConfig)
	if err != nil {
		return nil, err
	}

	// Convert to transport Response using helper methods
	respondedAt := time.Time{}
	if status.RespondedAt != nil {
		respondedAt = *status.RespondedAt
	}
	return &Response{
		ID:                status.GetID(),
		Status:            status.GetStatus(),
		EphemeralPublic:   status.GetEphemeralPublic(),
		EncryptedResponse: status.GetEncryptedResponse(),
		ResponseNonce:     status.GetResponseNonce(),
		RespondedAt:       respondedAt,
		ExpiresAt:         status.GetExpiresAt(),
	}, nil
}
