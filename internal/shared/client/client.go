// Package client provides HTTP communication with the backend service.
package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	authapi "github.com/ackagent/api/go/auth"
	relayapi "github.com/ackagent/api/go/relay"
	"github.com/ackagent/cli/internal/shared/log"
	"github.com/ackagent/cli/internal/shared/version"
)

var httpLog = log.New("http")

var (
	ErrTimeout    = errors.New("timeout waiting for response")
	ErrExpired    = errors.New("request expired")
	ErrRejected   = errors.New("request rejected")
	ErrNotFound   = errors.New("not found")
	ErrBadRequest = errors.New("bad request")
	ErrServer     = errors.New("server error")
)

// userAgent returns the User-Agent string for HTTP requests.
func userAgent() string {
	return "ackagent-cli/" + version.Version
}

// Client handles communication with the backend service.
// It uses generated OpenAPI clients for relay and auth services internally.
type Client struct {
	baseURL     string
	deviceID    string
	accessToken string
	httpClient  *http.Client
	relayAPI    *relayapi.ClientWithResponses
	authAPI     *authapi.ClientWithResponses
}

// NewClient creates a new backend client with generated relay and auth API clients.
func NewClient(baseURL, deviceID string) (*Client, error) {
	if _, err := url.ParseRequestURI(baseURL); err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	httpClient := &http.Client{
		Timeout: 10 * time.Second, // Standard request timeout
	}

	c := &Client{
		baseURL:    baseURL,
		deviceID:   deviceID,
		httpClient: httpClient,
	}

	// Common request editor that adds standard headers.
	// The closure captures c to read the current accessToken at call time.
	headerEditor := func(ctx context.Context, req *http.Request) error {
		req.Header.Set("User-Agent", userAgent())
		req.Header.Set("X-Device-ID", c.deviceID)
		if c.accessToken != "" {
			req.Header.Set("Authorization", "Bearer "+c.accessToken)
		}
		return nil
	}

	relayClient, err := relayapi.NewClientWithResponses(baseURL,
		relayapi.WithHTTPClient(httpClient),
		relayapi.WithRequestEditorFn(relayapi.RequestEditorFn(headerEditor)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create relay API client: %w", err)
	}
	c.relayAPI = relayClient

	authClient, err := authapi.NewClientWithResponses(baseURL,
		authapi.WithHTTPClient(httpClient),
		authapi.WithRequestEditorFn(authapi.RequestEditorFn(headerEditor)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth API client: %w", err)
	}
	c.authAPI = authClient

	return c, nil
}

// SetAccessToken sets the OIDC access token for authenticated requests.
func (c *Client) SetAccessToken(token string) {
	c.accessToken = token
}

// Login Session Endpoints (Multi-Device)

// IssuerPublicKeyInfo is an alias for the generated auth.IssuerPublicKeyInfo type.
type IssuerPublicKeyInfo = authapi.IssuerPublicKeyInfo

// ListUserDevices gets the list of approver devices for a user via the generated auth API client.
// Returns the generated ApproverInfo slice directly — callers dereference pointer fields inline.
func (c *Client) ListUserDevices(ctx context.Context, userID, accessToken string) ([]authapi.ApproverInfo, error) {
	httpLog.Debug("GET users/%s/approvers", userID)

	// Use per-request editor to override the access token for this call.
	authEditor := authapi.RequestEditorFn(func(_ context.Context, req *http.Request) error {
		req.Header.Set("Authorization", "Bearer "+accessToken)
		return nil
	})

	resp, err := c.authAPI.UserApproversListWithResponse(ctx, userID, authEditor)
	if err != nil {
		return nil, err
	}

	httpLog.Debug("GET users/%s/approvers status=%d", userID, resp.StatusCode())

	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("failed to list devices: %d - %s", resp.StatusCode(), string(resp.Body))
	}

	if resp.JSON200 == nil || resp.JSON200.Approvers == nil {
		return nil, nil
	}

	return *resp.JSON200.Approvers, nil
}

// GetCredentialIssuerPublicKey fetches and selects the best issuer public key for
// BBS+ anonymous attestation verification.
//
// Selection policy:
//  1. Prefer the newest non-rotated key.
//  2. If all keys are rotated, fall back to the newest key.
func (c *Client) GetCredentialIssuerPublicKey(ctx context.Context) ([]byte, error) {
	httpLog.Debug("GET credentials/public-key")

	resp, err := c.authAPI.CredentialsGetPublicKeyWithResponse(ctx)
	if err != nil {
		return nil, err
	}

	httpLog.Debug("GET credentials/public-key status=%d", resp.StatusCode())

	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf(
			"failed to fetch credential issuer public keys: %d - %s",
			resp.StatusCode(),
			string(resp.Body),
		)
	}
	if resp.JSON200 == nil || len(*resp.JSON200) == 0 {
		return nil, fmt.Errorf("no credential issuer public keys returned")
	}

	selected := selectCredentialIssuerPublicKey(*resp.JSON200)
	if selected == nil {
		return nil, fmt.Errorf("no usable credential issuer public key returned")
	}

	keyCopy := make([]byte, len(selected.PublicKey))
	copy(keyCopy, selected.PublicKey)
	return keyCopy, nil
}

// GetAllCredentialIssuerPublicKeys fetches all readable issuer public keys.
// Returns the full array for multi-key verification during attestation.
func (c *Client) GetAllCredentialIssuerPublicKeys(ctx context.Context) ([]authapi.IssuerPublicKeyInfo, error) {
	httpLog.Debug("GET credentials/public-key (all)")

	resp, err := c.authAPI.CredentialsGetPublicKeyWithResponse(ctx)
	if err != nil {
		return nil, err
	}

	httpLog.Debug("GET credentials/public-key (all) status=%d", resp.StatusCode())

	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf(
			"failed to fetch credential issuer public keys: %d - %s",
			resp.StatusCode(),
			string(resp.Body),
		)
	}
	if resp.JSON200 == nil || len(*resp.JSON200) == 0 {
		return nil, fmt.Errorf("no credential issuer public keys returned")
	}

	return *resp.JSON200, nil
}

func selectCredentialIssuerPublicKey(
	keys []authapi.IssuerPublicKeyInfo,
) *authapi.IssuerPublicKeyInfo {
	var newestActive *authapi.IssuerPublicKeyInfo
	var newestAny *authapi.IssuerPublicKeyInfo

	for i := range keys {
		key := &keys[i]
		if len(key.PublicKey) == 0 {
			continue
		}

		if newestAny == nil || key.CreatedAt.After(newestAny.CreatedAt) {
			newestAny = key
		}
		if key.RotatedAt == nil &&
			(newestActive == nil || key.CreatedAt.After(newestActive.CreatedAt)) {
			newestActive = key
		}
	}

	if newestActive != nil {
		return newestActive
	}
	return newestAny
}

// Attestation Endpoints

// AttestationData is an alias for the generated auth.AttestationData type.
type AttestationData = authapi.AttestationData

// GetAttestation retrieves attestation data for a device via the generated auth API client.
// The approverId parameter is the UUID of the approver device.
func (c *Client) GetAttestation(ctx context.Context, approverId, accessToken string) (*AttestationData, error) {
	httpLog.Debug("GET approvers/%s/attestation", approverId)

	// Use per-request editor to set the access token for this call.
	authEditor := authapi.RequestEditorFn(func(_ context.Context, req *http.Request) error {
		req.Header.Set("Authorization", "Bearer "+accessToken)
		return nil
	})

	resp, err := c.authAPI.ApproverAttestationGetWithResponse(ctx, approverId, authEditor)
	if err != nil {
		return nil, err
	}

	httpLog.Debug("GET approvers/%s/attestation status=%d", approverId, resp.StatusCode())

	switch resp.StatusCode() {
	case http.StatusOK:
		if resp.JSON200 == nil {
			return nil, fmt.Errorf("unexpected nil response body")
		}
		if resp.JSON200.Attestation == nil {
			return nil, fmt.Errorf("no attestation data for device")
		}
		return resp.JSON200.Attestation, nil
	case http.StatusNotFound:
		return nil, ErrNotFound
	case http.StatusForbidden:
		return nil, fmt.Errorf("device belongs to different user")
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("authentication required")
	default:
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode(), string(resp.Body))
	}
}

// SessionTokensResponse is the generated auth.GetRequesterSessionTokensResponse type.
// Use generated type directly to prevent spec drift.
type SessionTokensResponse = authapi.GetRequesterSessionTokensResponse

// GetSessionTokens gets OIDC tokens for a verified requester session (no auth required).
// The tokenClaimSecret must be provided for session fixation prevention.
func (c *Client) GetSessionTokens(ctx context.Context, sessionID, tokenClaimSecret string) (*SessionTokensResponse, error) {
	httpLog.Debug("GET requester-sessions/%s/tokens", sessionID)

	// The secret query parameter is not in the OpenAPI spec, so we add it via a request editor.
	secretEditor := authapi.RequestEditorFn(func(_ context.Context, req *http.Request) error {
		q := req.URL.Query()
		q.Set("secret", tokenClaimSecret)
		req.URL.RawQuery = q.Encode()
		return nil
	})

	resp, err := c.authAPI.RequesterSessionTokensGetWithResponse(ctx, sessionID, secretEditor)
	if err != nil {
		return nil, err
	}

	httpLog.Debug("GET requester-sessions/%s/tokens status=%d", sessionID, resp.StatusCode())

	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("get session tokens failed: %d - %s", resp.StatusCode(), string(resp.Body))
	}

	if resp.JSON200 == nil {
		return nil, fmt.Errorf("unexpected nil response body")
	}

	return resp.JSON200, nil
}

// Requester Session Endpoints (CLI login flow)

// CreateRequesterSessionRequest is the generated auth.CreateRequesterSessionRequest type.
type CreateRequesterSessionRequest = authapi.CreateRequesterSessionRequest

// CreateRequesterSessionResponse is the generated auth.CreateRequesterSessionResponse type.
type CreateRequesterSessionResponse = authapi.CreateRequesterSessionResponse

// CreateRequesterSession creates a requester session (no auth required) via the generated auth API client.
// The session starts unclaimed and will be claimed by iOS after scanning the QR code.
func (c *Client) CreateRequesterSession(ctx context.Context, req *CreateRequesterSessionRequest) (*CreateRequesterSessionResponse, error) {
	httpLog.Debug("POST requester-sessions")

	resp, err := c.authAPI.RequesterSessionsCreateWithResponse(ctx, *req)
	if err != nil {
		return nil, err
	}

	httpLog.Debug("POST requester-sessions status=%d", resp.StatusCode())

	if resp.StatusCode() != http.StatusCreated && resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("create requester session failed: %d - %s", resp.StatusCode(), string(resp.Body))
	}

	if resp.JSON201 == nil {
		// Fall back to parsing the body directly for 200 responses.
		var result CreateRequesterSessionResponse
		if err := json.Unmarshal(resp.Body, &result); err != nil {
			return nil, err
		}
		return &result, nil
	}

	return resp.JSON201, nil
}

// GetRequesterSessionStatus gets the status of a requester session via the generated auth API client.
// Returns the generated type directly — callers dereference pointer fields inline.
func (c *Client) GetRequesterSessionStatus(ctx context.Context, sessionID string) (*authapi.GetRequesterSessionStatusResponse, error) {
	httpLog.Debug("GET requester-sessions/%s/status", sessionID)

	resp, err := c.authAPI.RequesterSessionStatusGetWithResponse(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	httpLog.Debug("GET requester-sessions/%s/status status=%d", sessionID, resp.StatusCode())

	switch resp.StatusCode() {
	case http.StatusOK:
		if resp.JSON200 == nil {
			return nil, fmt.Errorf("unexpected nil response body")
		}
		return resp.JSON200, nil
	case http.StatusNotFound:
		return nil, ErrNotFound
	case http.StatusGone:
		return nil, ErrExpired
	default:
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode())
	}
}

// PollRequesterSession polls until the requester session is verified or timeout.
func (c *Client) PollRequesterSession(ctx context.Context, sessionID string, timeout time.Duration, cfg PollConfig) (*authapi.GetRequesterSessionStatusResponse, error) {
	return poll(ctx, timeout, cfg,
		func(ctx context.Context) (*authapi.GetRequesterSessionStatusResponse, error) {
			return c.GetRequesterSessionStatus(ctx, sessionID)
		},
		func(status *authapi.GetRequesterSessionStatusResponse) (bool, error) {
			s := ""
			if status.Status != nil {
				s = string(*status.Status)
			}
			switch s {
			case "verified":
				return true, nil
			case "rejected":
				return true, ErrRejected
			case "expired":
				return true, ErrExpired
			case "pending", "claimed":
				return false, nil
			default:
				return true, fmt.Errorf("unknown status: %s", s)
			}
		},
	)
}
