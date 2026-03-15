package main

import (
	"encoding/json"
	"fmt"
	"time"

	protocol "github.com/ackagent/api/go/protocol"
)

// EnrollRequest is sent to iOS for key enrollment.
// JSON tags use camelCase to match the OpenAPI spec (protocol.EnrollPayload).
type EnrollRequest struct {
	RequestID   string                            `json:"requestId"`
	Type        protocol.EnrollPayloadType        `json:"type"`
	Purpose     protocol.AckAgentCommonKeyPurpose `json:"purpose"`
	Algorithm   int                               `json:"algorithm"`
	Challenge   []byte                            `json:"challenge"`
	Application string                            `json:"application"`
	Flags       uint8                             `json:"flags"`
	Timestamp   int64                             `json:"timestamp"`
	Display     *protocol.GenericDisplaySchema    `json:"display,omitempty"`
	SourceInfo  *protocol.SourceInfo              `json:"sourceInfo,omitempty"`
}

// SignRequest is sent to iOS for signing.
// JSON tags use camelCase to match the OpenAPI spec (protocol.SshAuthPayload).
type SignRequest struct {
	RequestID   string                         `json:"requestId"`
	Type        protocol.SshAuthPayloadType    `json:"type"`
	IOSKeyID    string                         `json:"iosKeyId"`
	RawData     []byte                         `json:"rawData"`
	Application string                         `json:"application"`
	Flags       uint8                          `json:"flags"`
	Timestamp   int64                          `json:"timestamp"`
	Command     string                         `json:"command,omitempty"`
	Display     *protocol.GenericDisplaySchema `json:"display,omitempty"`
	SourceInfo  *protocol.SourceInfo           `json:"sourceInfo,omitempty"`
}

// KeyHandleData contains the data stored in a key handle.
type KeyHandleData struct {
	Version     int    `json:"v"`
	IOSKeyID    string `json:"k"`
	IOSDeviceID string `json:"d"`
	Application string `json:"a"`
	CreatedAt   int64  `json:"t"`
}

const keyHandleMagic uint32 = 0x41505052 // "APPR" in little-endian

func buildKeyHandle(iosKeyID, iosDeviceID, application string) []byte {
	data := KeyHandleData{
		Version:     1,
		IOSKeyID:    iosKeyID,
		IOSDeviceID: iosDeviceID,
		Application: application,
		CreatedAt:   time.Now().Unix(),
	}

	jsonData, _ := json.Marshal(data)

	// Format: [4-byte magic][4-byte length][JSON data]
	result := make([]byte, 8+len(jsonData))
	magic := keyHandleMagic
	length := uint32(len(jsonData))
	result[0] = byte(magic)
	result[1] = byte(magic >> 8)
	result[2] = byte(magic >> 16)
	result[3] = byte(magic >> 24)
	result[4] = byte(length)
	result[5] = byte(length >> 8)
	result[6] = byte(length >> 16)
	result[7] = byte(length >> 24)
	copy(result[8:], jsonData)

	return result
}

func parseKeyHandle(handle []byte) (*KeyHandleData, error) {
	if len(handle) < 8 {
		return nil, fmt.Errorf("key handle too short")
	}

	magic := uint32(handle[0]) | uint32(handle[1])<<8 | uint32(handle[2])<<16 | uint32(handle[3])<<24
	if magic != keyHandleMagic {
		return nil, fmt.Errorf("invalid key handle magic")
	}

	length := uint32(handle[4]) | uint32(handle[5])<<8 | uint32(handle[6])<<16 | uint32(handle[7])<<24
	if int(length) > len(handle)-8 {
		return nil, fmt.Errorf("key handle length mismatch")
	}

	var data KeyHandleData
	if err := json.Unmarshal(handle[8:8+length], &data); err != nil {
		return nil, err
	}

	return &data, nil
}
