package transport

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestBLEFrameEncodeDecode(t *testing.T) {
	payload := []byte(`{"id":"123"}`)
	frame, err := encodeBLEFrame(bleMessageTypeRequest, payload)
	if err != nil {
		t.Fatalf("encodeBLEFrame failed: %v", err)
	}

	decoded, err := decodeBLEFrame(frame)
	if err != nil {
		t.Fatalf("decodeBLEFrame failed: %v", err)
	}
	if decoded.messageType != bleMessageTypeRequest {
		t.Fatalf("message type mismatch: got %d want %d", decoded.messageType, bleMessageTypeRequest)
	}
	if string(decoded.payload) != string(payload) {
		t.Fatalf("payload mismatch: got %s want %s", decoded.payload, payload)
	}
}

func TestBLERequestJSONFormat(t *testing.T) {
	req := &Request{
		ID:               "req-1",
		RequesterID:      "requester-1",
		KeyID:            "",
		SigningPublicKey: "",
		EphemeralPublic:  []byte{1, 2, 3, 4},
		EncryptedPayload: []byte{5, 6, 7},
		PayloadNonce:     []byte{8, 9},
		ExpiresIn:        120,
		Timestamp:        123456789,
	}

	payload, err := encodeBLERequest(req)
	if err != nil {
		t.Fatalf("encodeBLERequest failed: %v", err)
	}

	var data map[string]any
	if err := json.Unmarshal(payload, &data); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if _, ok := data["requesterID"]; !ok {
		t.Fatalf("missing requesterID field")
	}
	if _, ok := data["ephemeralPublic"]; !ok {
		t.Fatalf("missing ephemeralPublic field")
	}

	encoded := data["ephemeralPublic"].(string)
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("base64 decode failed: %v", err)
	}
	if string(decoded) != string(req.EphemeralPublic) {
		t.Fatalf("ephemeralPublic mismatch")
	}
}
