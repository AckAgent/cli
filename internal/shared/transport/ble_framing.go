package transport

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
)

const (
	bleMessageTypeRequest  uint16 = 0x0001
	bleMessageTypeResponse uint16 = 0x0002

	bleMaxMessageSize uint32 = 1024 * 1024
)

// bleFrame represents a framed local transport message.
type bleFrame struct {
	messageType uint16
	payload     []byte
}

// encodeBLEFrame encodes a framed message with length prefix and type.
func encodeBLEFrame(messageType uint16, payload []byte) ([]byte, error) {
	length := uint32(2 + len(payload))
	if length > bleMaxMessageSize {
		return nil, fmt.Errorf("message too large: %d", length)
	}
	if length < 2 {
		return nil, fmt.Errorf("message too small: %d", length)
	}

	data := make([]byte, 4+length)
	// Length (4 bytes, big-endian)
	data[0] = byte(length >> 24)
	data[1] = byte(length >> 16)
	data[2] = byte(length >> 8)
	data[3] = byte(length)

	// Type (2 bytes, big-endian)
	data[4] = byte(messageType >> 8)
	data[5] = byte(messageType)

	copy(data[6:], payload)
	return data, nil
}

// decodeBLEFrame parses a framed message and returns its type and payload.
func decodeBLEFrame(data []byte) (*bleFrame, error) {
	if len(data) < 6 {
		return nil, fmt.Errorf("frame too short")
	}
	length := uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	if length > bleMaxMessageSize {
		return nil, fmt.Errorf("message too large: %d", length)
	}
	if length < 2 {
		return nil, fmt.Errorf("message too small: %d", length)
	}
	if len(data) < int(4+length) {
		return nil, fmt.Errorf("incomplete frame")
	}

	messageType := uint16(data[4])<<8 | uint16(data[5])
	payload := data[6 : 4+length]
	return &bleFrame{messageType: messageType, payload: payload}, nil
}

// bleLocalRequest is the JSON payload for BLE local transport requests.
type bleLocalRequest struct {
	ID               string               `json:"id"`
	RequesterID      string               `json:"requesterID"`
	KeyID            string               `json:"keyID,omitempty"`
	SigningPublicKey string               `json:"signingPublicKey,omitempty"`
	EphemeralPublic  []byte               `json:"ephemeralPublic"`
	EncryptedPayload []byte               `json:"encryptedPayload"`
	PayloadNonce     []byte               `json:"payloadNonce"`
	WrappedKeys      []bleLocalWrappedKey `json:"wrappedKeys,omitempty"`
	ExpiresIn        int                  `json:"expiresIn"`
	Timestamp        int64                `json:"timestamp"`
}

// bleLocalWrappedKey is the JSON payload for wrapped keys.
type bleLocalWrappedKey struct {
	EncryptionPublicKey string `json:"encryptionPublicKey"`
	WrappedKey          []byte `json:"wrappedKey"`
	WrappedKeyNonce     []byte `json:"wrappedKeyNonce"`
	EphemeralPublic     []byte `json:"ephemeralPublic"`
}

// bleLocalResponse is the JSON payload for BLE local transport responses.
type bleLocalResponse struct {
	ID                string `json:"id"`
	Status            string `json:"status"`
	EphemeralPublic   []byte `json:"ephemeralPublic,omitempty"`
	EncryptedResponse []byte `json:"encryptedResponse,omitempty"`
	ResponseNonce     []byte `json:"responseNonce,omitempty"`
}

// encodeBLERequest encodes a transport request into BLE JSON payload.
func encodeBLERequest(req *Request) ([]byte, error) {
	localReq := bleLocalRequest{
		ID:               req.ID,
		RequesterID:      req.RequesterID,
		KeyID:            req.KeyID,
		SigningPublicKey: req.SigningPublicKey,
		EphemeralPublic:  req.EphemeralPublic,
		EncryptedPayload: req.EncryptedPayload,
		PayloadNonce:     req.PayloadNonce,
		ExpiresIn:        req.ExpiresIn,
		Timestamp:        req.Timestamp,
	}

	if len(req.WrappedKeys) > 0 {
		localReq.WrappedKeys = make([]bleLocalWrappedKey, 0, len(req.WrappedKeys))
		for _, wk := range req.WrappedKeys {
			ephPub, _ := hex.DecodeString(wk.RequesterEphemeralKeyHex)
			localReq.WrappedKeys = append(localReq.WrappedKeys, bleLocalWrappedKey{
				EncryptionPublicKey: wk.EncryptionPublicKeyHex,
				WrappedKey:          wk.WrappedKey,
				WrappedKeyNonce:     wk.WrappedKeyNonce,
				EphemeralPublic:     ephPub,
			})
		}
	}

	return json.Marshal(localReq)
}

// decodeBLEResponse decodes a BLE JSON response payload into transport response.
func decodeBLEResponse(payload []byte) (*Response, error) {
	var localResp bleLocalResponse
	if err := json.Unmarshal(payload, &localResp); err != nil {
		return nil, err
	}

	return &Response{
		ID:                localResp.ID,
		Status:            localResp.Status,
		EphemeralPublic:   localResp.EphemeralPublic,
		EncryptedResponse: localResp.EncryptedResponse,
		ResponseNonce:     localResp.ResponseNonce,
	}, nil
}
