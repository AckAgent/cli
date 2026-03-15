package pam

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ackagent/cli/crypto"
	keyauthapi "github.com/ackagent/api/go/keyauth"
	relayapi "github.com/ackagent/api/go/relay"
	protocol "github.com/ackagent/api/go/protocol"
	sharedclient "github.com/ackagent/cli/internal/shared/client"
	"github.com/google/uuid"
)

// Client errors.
var (
	ErrNotAuthenticated = errors.New("not authenticated")
	ErrTimeout          = errors.New("request timed out")
	ErrRejected         = errors.New("request rejected by user")
	ErrExpired          = errors.New("request expired")
	ErrUserNotFound     = errors.New("user not found in organization")
	ErrNoDevices        = errors.New("no devices available for encryption")
)

// APIError represents an API error response.
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("API error (%d): %s", e.StatusCode, e.Message)
}

// Client is the HTTP client for AckAgent APIs.
type Client struct {
	httpClient       *http.Client
	loginURL         string
	relayURL         string
	oidcURL          string
	keyauthURL       string
	serviceAccountID string
	apiKey           string
	accessToken      string
	relayClient      *sharedclient.Client
	keyauthAPI       *keyauthapi.ClientWithResponses
}

// NewClient creates a new API client from config.
func NewClient(cfg *Config) *Client {
	relayClient, _ := sharedclient.NewClient(cfg.API.RelayURL, "pam")
	keyauthClient, _ := keyauthapi.NewClientWithResponses(cfg.API.KeyAuthURL)
	return &Client{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		loginURL:         cfg.API.LoginURL,
		relayURL:         cfg.API.RelayURL,
		oidcURL:          cfg.API.OIDCURL,
		keyauthURL:       cfg.API.KeyAuthURL,
		serviceAccountID: cfg.Organization.ServiceAccountID,
		apiKey:           cfg.Organization.APIKey,
		relayClient:      relayClient,
		keyauthAPI:       keyauthClient,
	}
}

func (c *Client) getRelayClient() (*sharedclient.Client, error) {
	if c.relayClient != nil {
		c.relayClient.SetAccessToken(c.accessToken)
		return c.relayClient, nil
	}

	relayClient, err := sharedclient.NewClient(c.relayURL, "pam")
	if err != nil {
		return nil, err
	}
	relayClient.SetAccessToken(c.accessToken)
	c.relayClient = relayClient
	return relayClient, nil
}

// tokenResponse represents the OAuth2 token response.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// Authenticate authenticates using OAuth2 client_credentials grant via the OIDC service.
// The service account ID is used as client_id and the API key as client_secret.
func (c *Client) Authenticate() error {
	if c.oidcURL == "" {
		return fmt.Errorf("OIDC URL not configured")
	}
	if c.serviceAccountID == "" || c.apiKey == "" {
		return fmt.Errorf("service account credentials not configured")
	}

	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.serviceAccountID},
		"client_secret": {c.apiKey},
		"scope":         {"relay:request"},
	}

	tokenURL := fmt.Sprintf("%s/oauth/token", c.oidcURL)
	resp, err := c.httpClient.Post(tokenURL, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to send token request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return &APIError{
			StatusCode: resp.StatusCode,
			Message:    string(respBody),
		}
	}

	var tokenResp tokenResponse
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return fmt.Errorf("failed to parse token response: %w", err)
	}
	c.accessToken = tokenResp.AccessToken
	if c.relayClient != nil {
		c.relayClient.SetAccessToken(c.accessToken)
	}
	return nil
}

// SendPamRequest sends a PAM authentication request to the relay with E2E encryption.
// Returns the request ID string, request ID bytes (for key derivation), and the
// ephemeral private key (for response decryption).
func (c *Client) SendPamRequest(
	request *protocol.PamAuthPayload,
	requesterID string,
	devices []crypto.DeviceKey,
	timeoutSecs int64,
) (requestIDStr string, requestIDBytes []byte, ephemeralPrivate []byte, err error) {
	if c.accessToken == "" {
		return "", nil, nil, ErrNotAuthenticated
	}

	if len(devices) == 0 {
		return "", nil, nil, ErrNoDevices
	}

	// Generate dedicated ephemeral keypair for response decryption (ECDH with approver)
	ephemeral, err := crypto.GenerateKeyPair()
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	// Generate request ID
	requestID := uuid.New()
	ridBytes := requestID[:]

	// Serialize payload to JSON
	payload, err := json.Marshal(request)
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Encrypt for all devices using the shared crypto package
	encrypted, err := crypto.EncryptForMultipleDevices(payload, devices, ridBytes)
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to encrypt request: %w", err)
	}

	// Convert wrapped keys to API format (using generated types directly)
	wrappedKeys := make([]relayapi.WrappedKey, 0, len(encrypted.WrappedKeys))
	for _, wk := range encrypted.WrappedKeys {
		wrappedKeys = append(wrappedKeys, relayapi.WrappedKey{
			EncryptionPublicKeyHex:   wk.EncryptionPublicKeyHex,
			WrappedKey:               wk.WrappedKey,
			WrappedKeyNonce:          wk.WrappedKeyNonce,
			RequesterEphemeralKeyHex: wk.RequesterEphemeralKeyHex,
		})
	}

	relayClient, err := c.getRelayClient()
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to initialize relay client: %w", err)
	}

	expiresIn := int32(timeoutSecs)
	apiReq := &relayapi.CreateSigningRequest{
		Id:                       requestID.String(),
		RequesterId:              requesterID,
		RequesterEphemeralKeyHex: hex.EncodeToString(ephemeral.PublicKey[:]),
		EncryptedPayload:         encrypted.EncryptedPayload,
		PayloadNonce:             encrypted.PayloadNonce,
		WrappedKeys:              &wrappedKeys,
		ExpiresIn:                &expiresIn,
		Timestamp:                time.Now().UnixMilli(),
	}

	resp, err := relayClient.CreateSigningRequest(context.Background(), apiReq)
	if err != nil {
		if errors.Is(err, sharedclient.ErrBadRequest) {
			return "", nil, nil, &APIError{StatusCode: http.StatusBadRequest, Message: err.Error()}
		}
		if strings.Contains(err.Error(), "status 404") {
			return "", nil, nil, ErrUserNotFound
		}
		return "", nil, nil, fmt.Errorf("failed to create relay request: %w", err)
	}

	requestIDStr = resp.GetID()
	if requestIDStr == "" {
		return "", nil, nil, fmt.Errorf("missing id in relay response")
	}

	return requestIDStr, ridBytes, ephemeral.PrivateKey[:], nil
}

// PollRequest polls for the status of a request.
// Returns a RelayResponseStatus with encrypted fields when the status is "responded".
func (c *Client) PollRequest(requestID string) (*RelayResponseStatus, error) {
	if c.accessToken == "" {
		return nil, ErrNotAuthenticated
	}

	relayClient, err := c.getRelayClient()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize relay client: %w", err)
	}

	status, err := relayClient.GetRequestStatus(context.Background(), requestID)
	if err != nil {
		if errors.Is(err, sharedclient.ErrExpired) {
			return &RelayResponseStatus{ID: requestID, Status: "expired"}, nil
		}
		if errors.Is(err, sharedclient.ErrNotFound) {
			return nil, &APIError{
				StatusCode: http.StatusNotFound,
				Message:    "request not found",
			}
		}
		// Preserve legacy APIError behavior for server-side status failures.
		if strings.HasPrefix(err.Error(), "unexpected status: ") {
			rawCode := strings.TrimSpace(strings.TrimPrefix(err.Error(), "unexpected status: "))
			if statusCode, parseErr := strconv.Atoi(rawCode); parseErr == nil {
				return nil, &APIError{
					StatusCode: statusCode,
					Message:    "failed to fetch request status",
				}
			}
		}
		return nil, fmt.Errorf("failed to fetch request status: %w", err)
	}

	result := &RelayResponseStatus{}
	result.ID = status.GetID()
	result.Status = status.GetStatus()
	result.EncryptedResponse = status.GetEncryptedResponse()
	result.ApproverEphemeralKey = status.GetEphemeralPublic()
	result.ResponseNonce = status.GetResponseNonce()

	return result, nil
}

// WaitForResponse polls for the request result with the specified timeout.
// Returns the raw RelayResponseStatus with encrypted fields (decryption is done by the caller).
func (c *Client) WaitForResponse(requestID string, timeoutSecs, pollIntervalMs int64) (*RelayResponseStatus, error) {
	relayClient, err := c.getRelayClient()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize relay client: %w", err)
	}

	pollConfig := sharedclient.PollConfig{
		InitialInterval: time.Duration(pollIntervalMs) * time.Millisecond,
		MaxInterval:     time.Duration(pollIntervalMs) * time.Millisecond,
		Multiplier:      1.0,
	}

	status, err := relayClient.PollForResponse(context.Background(), requestID, time.Duration(timeoutSecs)*time.Second, pollConfig)
	if err != nil {
		if errors.Is(err, sharedclient.ErrTimeout) {
			return nil, ErrTimeout
		}
		if errors.Is(err, sharedclient.ErrExpired) {
			return nil, ErrExpired
		}
		return nil, err
	}

	return &RelayResponseStatus{
		ID:                   status.GetID(),
		Status:               status.GetStatus(),
		EncryptedResponse:    status.GetEncryptedResponse(),
		ApproverEphemeralKey: status.GetEphemeralPublic(),
		ResponseNonce:        status.GetResponseNonce(),
	}, nil
}

// ListMemberDeviceKeys lists a user's device keys from the keyauth service.
func (c *Client) ListMemberDeviceKeys(orgID, email string) ([]keyauthapi.DeviceKeyInfo, error) {
	if c.accessToken == "" {
		return nil, ErrNotAuthenticated
	}

	if c.keyauthAPI == nil {
		return nil, fmt.Errorf("keyauth client not initialized")
	}

	resp, err := c.keyauthAPI.OrganizationMemberApproverKeysGetWithResponse(
		context.Background(), orgID, email,
		func(ctx context.Context, req *http.Request) error {
			req.Header.Set("Authorization", "Bearer "+c.accessToken)
			return nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch device keys: %w", err)
	}

	switch resp.StatusCode() {
	case http.StatusOK:
		if resp.JSON200 == nil {
			return nil, fmt.Errorf("unexpected nil response body")
		}
		return resp.JSON200.DeviceKeys, nil

	case http.StatusForbidden:
		return nil, &APIError{
			StatusCode: http.StatusForbidden,
			Message:    "not authorized to access member device keys",
		}

	default:
		return nil, &APIError{
			StatusCode: resp.StatusCode(),
			Message:    string(resp.Body),
		}
	}
}
