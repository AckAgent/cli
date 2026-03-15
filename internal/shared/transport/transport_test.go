package transport

import (
	"testing"
)

func TestTransportError_Error(t *testing.T) {
	err := &TransportError{
		Transport: "relay",
		Err:       errForTest("connection refused"),
	}

	got := err.Error()
	want := "relay: connection refused"
	if got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestTransportError_Unwrap(t *testing.T) {
	inner := errForTest("inner error")
	err := &TransportError{
		Transport: "ble",
		Err:       inner,
	}

	if err.Unwrap() != inner {
		t.Error("Unwrap() should return the inner error")
	}
}

// errForTest is a simple error type for testing.
type errForTest string

func (e errForTest) Error() string { return string(e) }

func TestRelayTransport_Name(t *testing.T) {
	rt := NewRelayTransport("http://localhost:8080", "device-1")
	if rt.Name() != "relay" {
		t.Errorf("Name() = %q, want %q", rt.Name(), "relay")
	}
}

func TestRelayTransport_Priority(t *testing.T) {
	rt := NewRelayTransport("http://localhost:8080", "device-1")
	if rt.Priority() != 50 {
		t.Errorf("Priority() = %d, want 50", rt.Priority())
	}
}

func TestRelayTransport_SetAccessToken(t *testing.T) {
	rt := NewRelayTransport("http://localhost:8080", "device-1")
	rt.SetAccessToken("test-token")
	if rt.accessToken != "test-token" {
		t.Errorf("accessToken = %q, want %q", rt.accessToken, "test-token")
	}
}

func TestDefaultManagerConfig(t *testing.T) {
	cfg := DefaultManagerConfig()
	if cfg.EnableBLETransport {
		t.Error("EnableBLETransport should default to false")
	}
	if cfg.BLEDevice != "" {
		t.Errorf("BLEDevice should default to empty, got %q", cfg.BLEDevice)
	}
}

func TestDecryptResponse_InvalidSignerPublicKey(t *testing.T) {
	_, err := DecryptResponse(
		make([]byte, 32), // ephemeral private
		make([]byte, 10), // wrong size signer public
		make([]byte, 16), // request ID
		make([]byte, 12), // nonce
		[]byte("ciphertext"),
	)
	if err == nil {
		t.Error("expected error for invalid signer public key size")
	}
}

func TestDecryptResponse_EmptyCiphertext(t *testing.T) {
	_, err := DecryptResponse(
		make([]byte, 32), // ephemeral private
		make([]byte, 33), // signer public (correct size)
		make([]byte, 16), // request ID
		make([]byte, 12), // nonce
		nil,              // empty ciphertext
	)
	if err == nil {
		t.Error("expected error for empty ciphertext")
	}
}

func TestResponse_Decrypt_InvalidKey(t *testing.T) {
	resp := &Response{
		EphemeralPublic:   make([]byte, 33),
		ResponseNonce:     make([]byte, 12),
		EncryptedResponse: []byte("encrypted"),
	}

	_, err := resp.Decrypt(make([]byte, 32), make([]byte, 16))
	// Should fail due to ECDH key derivation with invalid keys
	if err == nil {
		t.Error("expected error for invalid keys")
	}
}

func TestManager_Register(t *testing.T) {
	m := NewManager()

	// Empty manager
	if len(m.transports) != 0 {
		t.Errorf("new manager should have 0 transports, got %d", len(m.transports))
	}

	m.Register(&mockTransport{name: "a", priority: 1})
	if len(m.transports) != 1 {
		t.Errorf("after register, should have 1 transport, got %d", len(m.transports))
	}

	m.Register(&mockTransport{name: "b", priority: 2})
	if len(m.transports) != 2 {
		t.Errorf("after 2nd register, should have 2 transports, got %d", len(m.transports))
	}

	// Should mark as unsorted after register
	if m.sorted {
		t.Error("sorted should be false after register")
	}
}

func TestParseEnrollResponse_Success(t *testing.T) {
	// Note: uses generated protocol types; test basic parsing logic
	respJSON := `{"status":"approved"}`
	resp, err := ParseEnrollResponse([]byte(respJSON))
	if err != nil {
		t.Fatalf("ParseEnrollResponse() error = %v", err)
	}
	if resp == nil {
		t.Fatal("ParseEnrollResponse() returned nil")
	}
}

func TestParseEnrollResponse_InvalidJSON(t *testing.T) {
	_, err := ParseEnrollResponse([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParseEnrollResponse_ErrorCode(t *testing.T) {
	errCode := 100
	errMsg := "key not found"
	respJSON := `{"status":"error","errorCode":100,"errorMessage":"key not found"}`
	_, err := ParseEnrollResponse([]byte(respJSON))
	if err == nil {
		t.Error("expected error when errorCode is present")
	}
	_ = errCode
	_ = errMsg
}

func TestParseEnrollResponse_Rejected(t *testing.T) {
	respJSON := `{"status":"rejected"}`
	_, err := ParseEnrollResponse([]byte(respJSON))
	if err == nil {
		t.Error("expected error for rejected enrollment")
	}
}

func TestRequestBuilder_Chaining(t *testing.T) {
	// Test builder chaining doesn't panic and preserves values
	// We can't call Send (needs real config), but we can test the builder state

	// Create a basic config for the builder (not logged in)
	b := &RequestBuilder{
		expiresIn: 120,
	}

	b.WithKey("key-id", "pubkey-hex")
	if b.keyID != "key-id" {
		t.Errorf("keyID = %q, want key-id", b.keyID)
	}
	if b.signingPublicKey != "pubkey-hex" {
		t.Errorf("signingPublicKey = %q, want pubkey-hex", b.signingPublicKey)
	}

	b.WithExpiration(300)
	if b.expiresIn != 300 {
		t.Errorf("expiresIn = %d, want 300", b.expiresIn)
	}

	b.WithTimestamp(1234567890)
	if b.timestamp != 1234567890 {
		t.Errorf("timestamp = %d, want 1234567890", b.timestamp)
	}
}

func TestRequestBuilder_ErrorShortCircuits(t *testing.T) {
	// When builder has an error, chaining methods should be no-ops
	b := &RequestBuilder{
		err:       errForTest("initial error"),
		expiresIn: 120,
	}

	b.WithKey("key-id", "pubkey")
	if b.keyID != "" {
		t.Error("WithKey should be no-op when error is set")
	}

	b.WithExpiration(999)
	if b.expiresIn != 120 {
		t.Error("WithExpiration should be no-op when error is set")
	}

	b.WithTimestamp(999)
	if b.timestamp != 0 {
		t.Error("WithTimestamp should be no-op when error is set")
	}
}
