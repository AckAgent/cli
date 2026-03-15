package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	protocol "github.com/ackagent/api/go/protocol"
	"github.com/ackagent/cli/internal/shared/config"
)

// SendAndDecryptEnrollment sends an enrollment request and decrypts the response.
// Enrollment flows skip BBS+ attestation verification by design.
func SendAndDecryptEnrollment(ctx context.Context, cfg *config.Config, payload any, timeout time.Duration) ([]byte, error) {
	result, err := NewRequestBuilder(cfg).
		WithTimeout(timeout).
		WithExpiration(int(timeout.Seconds())).
		WithTimestamp(time.Now().UnixMilli()).
		Send(ctx, payload)
	if err != nil {
		return nil, err
	}

	switch result.Response.Status {
	case "responded":
		return result.DecryptWithoutAttestation()
	case "expired":
		return nil, fmt.Errorf("enrollment request expired")
	default:
		return nil, fmt.Errorf("unexpected status: %s", result.Response.Status)
	}
}

// ParseEnrollResponse parses and validates a common enrollment response payload.
func ParseEnrollResponse(decrypted []byte) (*protocol.EnrollResponse, error) {
	var response protocol.EnrollResponse
	if err := json.Unmarshal(decrypted, &response); err != nil {
		return nil, fmt.Errorf("failed to parse enrollment response: %w", err)
	}

	if response.ErrorCode != nil {
		errMsg := "unknown error"
		if response.ErrorMessage != nil {
			errMsg = *response.ErrorMessage
		}
		return nil, fmt.Errorf("enrollment failed: %s (code %d)", errMsg, *response.ErrorCode)
	}

	if response.Status != protocol.EnrollResponseStatusApproved {
		return nil, fmt.Errorf("enrollment rejected")
	}

	return &response, nil
}
