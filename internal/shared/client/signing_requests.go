package client

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"

	relayapi "github.com/ackagent/api/go/relay"
)

// WrappedKeyRequest is an alias for relayapi.WrappedKey (multi-device mode)
type WrappedKeyRequest = relayapi.WrappedKey

// SigningRequestResponse wraps the generated relayapi.CreateSigningResponse with helper methods.
type SigningRequestResponse struct {
	relayapi.CreateSigningResponse
}

// GetID returns the request ID, or empty string if not present.
func (r *SigningRequestResponse) GetID() string {
	if r.Id == nil {
		return ""
	}
	return *r.Id
}

// GetStatus returns the status, or empty string if not present.
func (r *SigningRequestResponse) GetStatus() string {
	if r.Status == nil {
		return ""
	}
	return *r.Status
}

// GetExpiresAt returns the expiration time, or zero time if not present.
func (r *SigningRequestResponse) GetExpiresAt() time.Time {
	if r.ExpiresAt == nil {
		return time.Time{}
	}
	return *r.ExpiresAt
}

// CreateSigningRequest creates a new signing request via the generated relay API client.
func (c *Client) CreateSigningRequest(ctx context.Context, req *relayapi.CreateSigningRequest) (*SigningRequestResponse, error) {
	httpLog.Debug("POST requests")
	start := time.Now()

	resp, err := c.relayAPI.RequestsCreateWithResponse(ctx, *req)
	if err != nil {
		httpLog.Error("POST requests failed: %v", err)
		return nil, err
	}

	httpLog.Debug("POST requests status=%d latency=%v", resp.StatusCode(), time.Since(start))

	switch resp.StatusCode() {
	case http.StatusOK:
		if resp.JSON200 == nil {
			return nil, fmt.Errorf("unexpected nil response body")
		}
		result := &SigningRequestResponse{*resp.JSON200}
		httpLog.Debug("request created id=%s", result.GetID())
		return result, nil
	case http.StatusAccepted:
		if resp.JSON202 == nil {
			return nil, fmt.Errorf("unexpected nil response body")
		}
		result := &SigningRequestResponse{*resp.JSON202}
		httpLog.Debug("request created id=%s", result.GetID())
		return result, nil
	case http.StatusBadRequest:
		httpLog.Warn("POST requests bad request")
		return nil, ErrBadRequest
	case http.StatusUnauthorized:
		httpLog.Warn("POST requests unauthorized")
		return nil, fmt.Errorf("authentication required: please run 'ackagent login' first")
	default:
		httpLog.Error("POST requests unexpected status %d: %s", resp.StatusCode(), string(resp.Body))
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode(), string(resp.Body))
	}
}

// RequestStatus wraps the generated relayapi.SigningRequestStatus with helper methods.
// Privacy: Backend only knows "pending", "responded", or "expired" - never "approved" or "rejected".
// The actual decision is E2E encrypted and must be decrypted by the requester.
type RequestStatus struct {
	relayapi.SigningRequestStatus
}

// GetID returns the request ID, or empty string if not present.
func (r *RequestStatus) GetID() string {
	if r.Id == nil {
		return ""
	}
	return *r.Id
}

// GetStatus returns the status, or empty string if not present.
func (r *RequestStatus) GetStatus() string {
	if r.Status == nil {
		return ""
	}
	return string(*r.Status)
}

// GetEphemeralPublic returns the approver's ephemeral public key, or nil if not present.
func (r *RequestStatus) GetEphemeralPublic() []byte {
	if r.ApproverEphemeralKeyHex == nil {
		return nil
	}
	key, err := hex.DecodeString(*r.ApproverEphemeralKeyHex)
	if err != nil {
		return nil
	}
	return key
}

// GetEncryptedResponse returns the encrypted response, or nil if not present.
func (r *RequestStatus) GetEncryptedResponse() []byte {
	if r.EncryptedResponse == nil {
		return nil
	}
	return *r.EncryptedResponse
}

// GetResponseNonce returns the response nonce, or nil if not present.
func (r *RequestStatus) GetResponseNonce() []byte {
	if r.ResponseNonce == nil {
		return nil
	}
	return *r.ResponseNonce
}

// GetExpiresAt returns the expiration time, or zero time if not present.
func (r *RequestStatus) GetExpiresAt() time.Time {
	if r.SigningRequestStatus.ExpiresAt == nil {
		return time.Time{}
	}
	return *r.SigningRequestStatus.ExpiresAt
}

// GetRequestStatus gets the current status of a signing request via the generated relay API client.
func (c *Client) GetRequestStatus(ctx context.Context, requestID string) (*RequestStatus, error) {
	httpLog.Debug("GET requests/%s", requestID)

	resp, err := c.relayAPI.RequestByIdGetWithResponse(ctx, requestID)
	if err != nil {
		return nil, err
	}

	httpLog.Debug("GET requests/%s status=%d", requestID, resp.StatusCode())

	switch resp.StatusCode() {
	case http.StatusOK:
		if resp.JSON200 == nil {
			return nil, fmt.Errorf("unexpected nil response body")
		}
		return &RequestStatus{*resp.JSON200}, nil
	case http.StatusNotFound:
		return nil, ErrNotFound
	case http.StatusGone:
		return nil, ErrExpired
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("authentication required")
	default:
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode())
	}
}

// PollForResponse polls until the request is completed or timeout
// Privacy: Backend returns "responded" (never "approved"/"rejected") - requester decrypts to learn decision
func (c *Client) PollForResponse(ctx context.Context, requestID string, timeout time.Duration, cfg PollConfig) (*RequestStatus, error) {
	httpLog.Debug("waiting for response id=%s timeout=%v", requestID, timeout)
	status, err := poll(ctx, timeout, cfg,
		func(ctx context.Context) (*RequestStatus, error) {
			return c.GetRequestStatus(ctx, requestID)
		},
		func(status *RequestStatus) (bool, error) {
			switch status.GetStatus() {
			case "responded":
				// Response received - caller must decrypt to determine if approved or rejected
				httpLog.Debug("response received id=%s", requestID)
				return true, nil
			case "expired":
				httpLog.Warn("request expired id=%s", requestID)
				return true, ErrExpired
			case "pending":
				return false, nil
			default:
				return true, fmt.Errorf("unknown status: %s", status.GetStatus())
			}
		},
	)
	if err != nil && !errors.Is(err, ErrExpired) {
		httpLog.Error("poll failed id=%s: %v", requestID, err)
	}
	return status, err
}
