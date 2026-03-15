package transport

import (
	"context"
	"testing"
	"time"

	"github.com/ackagent/cli/crypto"
	"github.com/ackagent/cli/internal/shared/client"
	"github.com/ackagent/cli/internal/shared/config"
)

func TestRelayTransport_SetPollConfig(t *testing.T) {
	rt := NewRelayTransport("http://localhost", "device-1")
	cfg := client.PollConfig{
		InitialInterval: 5 * time.Second,
		MaxInterval:     30 * time.Second,
		Multiplier:      2.0,
	}
	rt.SetPollConfig(cfg)
	if rt.pollConfig.InitialInterval != 5*time.Second {
		t.Errorf("InitialInterval = %v, want 5s", rt.pollConfig.InitialInterval)
	}
	if rt.pollConfig.MaxInterval != 30*time.Second {
		t.Errorf("MaxInterval = %v, want 30s", rt.pollConfig.MaxInterval)
	}
}

func TestRelayTransport_IsAvailable(t *testing.T) {
	rt := NewRelayTransport("http://localhost", "device-1")
	available, err := rt.IsAvailable(context.Background())
	if err != nil {
		t.Fatalf("IsAvailable() error = %v", err)
	}
	if !available {
		t.Error("relay transport should always report as available")
	}
}

func TestNewManagerWithConfig_NobleOff(t *testing.T) {
	cfg := config.NewDefault()

	m := NewManagerWithConfig(cfg, "my-token", ManagerConfig{
		EnableBLETransport: false,
	})

	if len(m.transports) != 1 {
		t.Fatalf("expected 1 transport (relay only), got %d", len(m.transports))
	}
	if m.transports[0].Name() != "relay" {
		t.Errorf("transport name = %q, want relay", m.transports[0].Name())
	}
}

func TestRequestBuilder_WithTimeout(t *testing.T) {
	cfg := config.NewDefault()
	// Not logged in, so builder will have an error, but we can still test chaining
	b := NewRequestBuilder(cfg)
	b.WithTimeout(30 * time.Second)
	// The error from not being logged in should propagate
	_, err := b.Send(context.Background(), nil)
	if err == nil {
		t.Error("expected error from not being logged in")
	}
}

func TestDecryptResponse_RoundTrip(t *testing.T) {
	// Generate two ephemeral key pairs (requester and signer)
	requester, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	signer, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	// Generate a request ID (16 bytes)
	requestID := make([]byte, 16)
	for i := range requestID {
		requestID[i] = byte(i)
	}

	// Encrypt with signer's perspective: derive key from signer_private + requester_public
	responseKey, err := crypto.DeriveResponseKey(signer.PrivateKey[:], requester.PublicKey[:], requestID)
	if err != nil {
		t.Fatalf("DeriveResponseKey() error = %v", err)
	}

	plaintext := []byte(`{"decision":"allow"}`)
	// crypto.Encrypt generates nonce internally: (key, plaintext, aad) → (ciphertext, nonce, err)
	ciphertext, nonce, err := crypto.Encrypt(responseKey, plaintext, requestID)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Decrypt from requester's perspective
	decrypted, err := DecryptResponse(
		requester.PrivateKey[:],
		signer.PublicKey[:],
		requestID,
		nonce,
		ciphertext,
	)
	if err != nil {
		t.Fatalf("DecryptResponse() error = %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestDecryptResponse_CorruptedCiphertext(t *testing.T) {
	requester, _ := crypto.GenerateKeyPair()
	signer, _ := crypto.GenerateKeyPair()
	requestID := make([]byte, 16)

	responseKey, _ := crypto.DeriveResponseKey(signer.PrivateKey[:], requester.PublicKey[:], requestID)
	ciphertext, nonce, _ := crypto.Encrypt(responseKey, []byte("test"), requestID)

	// Corrupt ciphertext
	ciphertext[0] ^= 0xFF

	_, err := DecryptResponse(
		requester.PrivateKey[:],
		signer.PublicKey[:],
		requestID,
		nonce,
		ciphertext,
	)
	if err == nil {
		t.Error("expected decryption error with corrupted ciphertext")
	}
}

func TestResponse_Decrypt_Method(t *testing.T) {
	requester, _ := crypto.GenerateKeyPair()
	signer, _ := crypto.GenerateKeyPair()
	requestID := make([]byte, 16)

	responseKey, _ := crypto.DeriveResponseKey(signer.PrivateKey[:], requester.PublicKey[:], requestID)
	plaintext := []byte(`{"status":"ok"}`)
	ciphertext, nonce, _ := crypto.Encrypt(responseKey, plaintext, requestID)

	resp := &Response{
		EphemeralPublic:   signer.PublicKey[:],
		EncryptedResponse: ciphertext,
		ResponseNonce:     nonce,
	}

	decrypted, err := resp.Decrypt(requester.PrivateKey[:], requestID)
	if err != nil {
		t.Fatalf("Response.Decrypt() error = %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestRequestResult_DecryptWithoutAttestation(t *testing.T) {
	requester, _ := crypto.GenerateKeyPair()
	signer, _ := crypto.GenerateKeyPair()
	requestID := make([]byte, 16)

	responseKey, _ := crypto.DeriveResponseKey(signer.PrivateKey[:], requester.PublicKey[:], requestID)
	plaintext := []byte(`{"test":"value"}`)
	ciphertext, nonce, _ := crypto.Encrypt(responseKey, plaintext, requestID)

	result := &RequestResult{
		Response: &Response{
			EphemeralPublic:   signer.PublicKey[:],
			EncryptedResponse: ciphertext,
			ResponseNonce:     nonce,
		},
		EphemeralPrivate: requester.PrivateKey[:],
		RequestID:        requestID,
	}

	decrypted, err := result.DecryptWithoutAttestation()
	if err != nil {
		t.Fatalf("DecryptWithoutAttestation() error = %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestManager_Send_PriorityOrder_TwoTransports(t *testing.T) {
	// Lower priority number = tried first
	m := NewManager()

	m.Register(&mockTransport{
		name:      "primary",
		priority:  10, // tried first (lowest number)
		available: true,
		response: &Response{
			ID:     "resp-primary",
			Status: "responded",
		},
	})
	m.Register(&mockTransport{
		name:      "secondary",
		priority:  50,
		available: true,
		response:  &Response{ID: "resp-secondary", Status: "responded"},
	})

	resp, err := m.Send(context.Background(), &Request{ID: "req-1"}, 5*time.Second)
	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if resp.ID != "resp-primary" {
		t.Errorf("response ID = %q, want resp-primary", resp.ID)
	}
}

func TestManager_Send_FallbackOnError_Extra(t *testing.T) {
	// Lower priority number = tried first, but if it fails, fallback to next
	m := NewManager()

	m.Register(&mockTransport{
		name:      "primary",
		priority:  10, // tried first but fails
		available: true,
		err:       &TransportError{Transport: "primary", Err: context.DeadlineExceeded},
	})
	m.Register(&mockTransport{
		name:      "fallback",
		priority:  50,
		available: true,
		response:  &Response{ID: "resp-fallback", Status: "responded"},
	})

	resp, err := m.Send(context.Background(), &Request{ID: "req-1"}, 5*time.Second)
	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if resp.ID != "resp-fallback" {
		t.Errorf("response ID = %q, want resp-fallback", resp.ID)
	}
}

func TestManager_Send_SkipsUnavailable_Extra(t *testing.T) {
	m := NewManager()

	m.Register(&mockTransport{
		name:      "unavailable",
		priority:  10, // tried first but unavailable
		available: false,
	})
	m.Register(&mockTransport{
		name:      "available",
		priority:  50,
		available: true,
		response:  &Response{ID: "resp-avail", Status: "responded"},
	})

	resp, err := m.Send(context.Background(), &Request{ID: "req-1"}, 5*time.Second)
	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if resp.ID != "resp-avail" {
		t.Errorf("response ID = %q, want resp-avail", resp.ID)
	}
}
