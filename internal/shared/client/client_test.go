package client

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	authapi "github.com/ackagent/api/go/auth"
	relayapi "github.com/ackagent/api/go/relay"
	protocol "github.com/ackagent/api/go/protocol"
)

func TestCreateSigningRequest(t *testing.T) {
	var receivedReq relayapi.CreateSigningRequest

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/requests" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != "POST" {
			t.Errorf("unexpected method: %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected content-type: %s", r.Header.Get("Content-Type"))
		}

		if err := json.NewDecoder(r.Body).Decode(&receivedReq); err != nil {
			t.Fatalf("failed to decode request: %v", err)
		}

		// Respond with the generated API type (which SigningRequestResponse wraps)
		id := receivedReq.Id
		status := "pending"
		expiresAt := time.Now().Add(5 * time.Minute)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(relayapi.CreateSigningResponse{
			Id:        &id,
			Status:    &status,
			ExpiresAt: &expiresAt,
		})
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "test-device")
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	expiresIn := int32(300)
	req := &relayapi.CreateSigningRequest{
		Id:                       "req-123",
		RequesterId:              "requester-456",
		RequesterEphemeralKeyHex: "0000000000000000000000000000000000000000000000000000000000000000",
		EncryptedPayload:         []byte("encrypted-data"),
		PayloadNonce:             make([]byte, 12),
		ExpiresIn:                &expiresIn,
		Timestamp:                time.Now().UnixMilli(),
	}

	resp, err := client.CreateSigningRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("CreateSigningRequest failed: %v", err)
	}

	if resp.GetID() != req.Id {
		t.Errorf("ID mismatch: got %v, want %v", resp.GetID(), req.Id)
	}
	if resp.GetStatus() != "pending" {
		t.Errorf("Status mismatch: got %v, want pending", resp.GetStatus())
	}

	// Verify request was received correctly
	if receivedReq.Id != req.Id {
		t.Errorf("received ID mismatch: got %v, want %v", receivedReq.Id, req.Id)
	}
}

func TestPollForResponse(t *testing.T) {
	pollCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pollCount++
		w.Header().Set("Content-Type", "application/json")

		// Return pending for first 2 polls, then responded
		// Privacy: backend returns "responded", requester decrypts to determine if approved/rejected
		id := "req-123"
		encResponse := []byte("encrypted-response")
		nonce := make([]byte, 12)
		if pollCount < 3 {
			status := relayapi.Pending
			json.NewEncoder(w).Encode(relayapi.SigningRequestStatus{
				Id:     &id,
				Status: &status,
			})
		} else {
			status := relayapi.Responded
			json.NewEncoder(w).Encode(relayapi.SigningRequestStatus{
				Id:                &id,
				Status:            &status,
				EncryptedResponse: &encResponse,
				ResponseNonce:     &nonce,
			})
		}
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "test-device")
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	cfg := PollConfig{
		InitialInterval: 10 * time.Millisecond,
		MaxInterval:     50 * time.Millisecond,
		Multiplier:      1.5,
	}

	status, err := client.PollForResponse(context.Background(), "req-123", 5*time.Second, cfg)
	if err != nil {
		t.Fatalf("PollForResponse failed: %v", err)
	}

	if status.GetStatus() != "responded" {
		t.Errorf("Status mismatch: got %v, want responded", status.GetStatus())
	}
	if status.GetEncryptedResponse() == nil {
		t.Error("EncryptedResponse should not be nil")
	}
	if pollCount != 3 {
		t.Errorf("expected 3 polls, got %d", pollCount)
	}
}

func TestPollForResponse_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Always return pending
		id := "req-123"
		status := relayapi.Pending
		json.NewEncoder(w).Encode(relayapi.SigningRequestStatus{
			Id:     &id,
			Status: &status,
		})
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "test-device")
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	cfg := PollConfig{
		InitialInterval: 10 * time.Millisecond,
		MaxInterval:     20 * time.Millisecond,
		Multiplier:      1.5,
	}

	_, err = client.PollForResponse(context.Background(), "req-123", 100*time.Millisecond, cfg)
	if err != ErrTimeout {
		t.Errorf("expected ErrTimeout, got: %v", err)
	}
}

func TestNewClient_InvalidURL(t *testing.T) {
	// NewClient should return an error for invalid URLs instead of silently leaving
	// API clients nil (which would cause panics on first use).
	_, err := NewClient("://invalid", "test-device")
	if err == nil {
		t.Error("expected error for invalid URL, got nil")
	}
}

func TestGetErrorCode(t *testing.T) {
	// nil code returns nil
	if got := getErrorCode(nil); got != nil {
		t.Errorf("getErrorCode(nil) = %v, want nil", got)
	}

	// non-nil code returns pointer to int
	code := protocol.AckAgentCommonSigningErrorCode(3)
	got := getErrorCode(&code)
	if got == nil {
		t.Fatal("getErrorCode(&3) = nil, want non-nil")
	}
	if *got != 3 {
		t.Errorf("getErrorCode(&3) = %d, want 3", *got)
	}
}

func TestGetErrorMessage(t *testing.T) {
	if got := getErrorMessage(nil); got != "" {
		t.Errorf("getErrorMessage(nil) = %q, want empty", got)
	}

	msg := "test error"
	if got := getErrorMessage(&msg); got != "test error" {
		t.Errorf("getErrorMessage(&msg) = %q, want %q", got, msg)
	}
}

func TestSigningError_AllCodes(t *testing.T) {
	tests := []struct {
		code    int
		wantNil bool
		wantSub string // substring expected in error message
	}{
		{1, false, "rejected"},
		{2, false, "expired"},
		{3, false, "unsupported algorithm"},
		{4, false, "invalid requester"},
		{5, false, "key not found"},
		{6, false, "internal error"},
		{99, false, "unknown error"},
	}

	for _, tt := range tests {
		code := tt.code
		err := signingError(&code, "details", "signing")
		if err == nil {
			t.Errorf("signingError(%d) = nil, want error", tt.code)
			continue
		}
		if tt.wantSub != "" {
			if got := err.Error(); !contains(got, tt.wantSub) {
				t.Errorf("signingError(%d) = %q, want substring %q", tt.code, got, tt.wantSub)
			}
		}
	}

	// nil code returns nil
	if err := signingError(nil, "msg", "signing"); err != nil {
		t.Errorf("signingError(nil) = %v, want nil", err)
	}
}

func TestResponseWrappers_Error(t *testing.T) {
	// SigningResponse with error code
	code := protocol.AckAgentCommonSigningErrorCode(1)
	msg := "user declined"
	sr := &SigningResponse{protocol.SignatureResponse{ErrorCode: &code, ErrorMessage: &msg}}
	if sr.IsSuccess() {
		t.Error("SigningResponse with error code should not be success")
	}
	if err := sr.Error(); err == nil {
		t.Error("SigningResponse.Error() should return error")
	}

	// GPGSignResponse with error code
	gr := &GPGSignResponse{protocol.GpgSignatureResponse{ErrorCode: &code, ErrorMessage: &msg}}
	if gr.IsSuccess() {
		t.Error("GPGSignResponse with error code should not be success")
	}
	if err := gr.Error(); err == nil {
		t.Error("GPGSignResponse.Error() should return error")
	}

	// GPGDecryptResponse with error code
	dr := &GPGDecryptResponse{protocol.GpgDecryptResponse{ErrorCode: &code, ErrorMessage: &msg}}
	if dr.IsSuccess() {
		t.Error("GPGDecryptResponse with error code should not be success")
	}
	if err := dr.Error(); err == nil {
		t.Error("GPGDecryptResponse.Error() should return error")
	}
}

func TestGetCredentialIssuerPublicKey_SelectsNewestActive(t *testing.T) {
	now := time.Now().UTC()
	activeOld := []byte("active-old")
	rotatedNew := []byte("rotated-new")
	activeNewest := []byte("active-newest")
	rotatedAt := now.Add(-30 * time.Minute)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/credentials/public-key" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("unexpected authorization header: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]authapi.IssuerPublicKeyInfo{
			{
				Id:        "key-active-old",
				Algorithm: "BBS-BLS12381-SHA256",
				PublicKey: activeOld,
				CreatedAt: now.Add(-2 * time.Hour),
			},
			{
				Id:        "key-rotated-new",
				Algorithm: "BBS-BLS12381-SHA256",
				PublicKey: rotatedNew,
				CreatedAt: now.Add(-5 * time.Minute),
				RotatedAt: &rotatedAt,
			},
			{
				Id:        "key-active-newest",
				Algorithm: "BBS-BLS12381-SHA256",
				PublicKey: activeNewest,
				CreatedAt: now.Add(-1 * time.Minute),
			},
		})
	}))
	defer server.Close()

	c, err := NewClient(server.URL, "test-device")
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	c.SetAccessToken("test-token")

	key, err := c.GetCredentialIssuerPublicKey(context.Background())
	if err != nil {
		t.Fatalf("GetCredentialIssuerPublicKey failed: %v", err)
	}

	if !bytes.Equal(key, activeNewest) {
		t.Fatalf("selected wrong key: got %q, want %q", string(key), string(activeNewest))
	}
}

func TestGetCredentialIssuerPublicKey_FallsBackToNewestWhenAllRotated(t *testing.T) {
	now := time.Now().UTC()
	rotatedOld := []byte("rotated-old")
	rotatedNewest := []byte("rotated-newest")
	rotatedAtOld := now.Add(-2 * time.Hour)
	rotatedAtNew := now.Add(-1 * time.Hour)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]authapi.IssuerPublicKeyInfo{
			{
				Id:        "key-rotated-old",
				Algorithm: "BBS-BLS12381-SHA256",
				PublicKey: rotatedOld,
				CreatedAt: now.Add(-3 * time.Hour),
				RotatedAt: &rotatedAtOld,
			},
			{
				Id:        "key-rotated-newest",
				Algorithm: "BBS-BLS12381-SHA256",
				PublicKey: rotatedNewest,
				CreatedAt: now.Add(-15 * time.Minute),
				RotatedAt: &rotatedAtNew,
			},
		})
	}))
	defer server.Close()

	c, err := NewClient(server.URL, "test-device")
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	key, err := c.GetCredentialIssuerPublicKey(context.Background())
	if err != nil {
		t.Fatalf("GetCredentialIssuerPublicKey failed: %v", err)
	}

	if !bytes.Equal(key, rotatedNewest) {
		t.Fatalf("selected wrong key: got %q, want %q", string(key), string(rotatedNewest))
	}
}

func TestGetCredentialIssuerPublicKey_EmptyKeySet(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]authapi.IssuerPublicKeyInfo{})
	}))
	defer server.Close()

	c, err := NewClient(server.URL, "test-device")
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	if _, err := c.GetCredentialIssuerPublicKey(context.Background()); err == nil {
		t.Fatal("expected error for empty key set")
	}
}

// contains checks if s contains substr (avoids importing strings for a single test helper).
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr))
}

func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
