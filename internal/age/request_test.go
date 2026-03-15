package age

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	protocol "github.com/ackagent/api/go/protocol"
)

func TestAgeUnwrapPayloadMarshalJSON(t *testing.T) {
	icon := "lock.open"
	tests := []struct {
		name    string
		request protocol.AgeUnwrapPayload
	}{
		{
			name: "basic request",
			request: protocol.AgeUnwrapPayload{
				Type:               protocol.AgeUnwrapPayloadTypeAgeUnwrap,
				EphemeralPublicHex: strings.Repeat("aa", 32),
				WrappedFileKey:     bytes.Repeat([]byte{0xBB}, 32),
				RecipientPublicHex: strings.Repeat("cc", 32),
				Display: &protocol.GenericDisplaySchema{
					Title: "Decrypt file?",
					Icon:  &icon,
					Fields: []protocol.DisplayField{
						{Label: "File", Value: "test.age"},
					},
				},
			},
		},
		{
			name: "request without display info",
			request: protocol.AgeUnwrapPayload{
				Type:               protocol.AgeUnwrapPayloadTypeAgeUnwrap,
				EphemeralPublicHex: strings.Repeat("11", 32),
				WrappedFileKey:     bytes.Repeat([]byte{0x22}, 32),
				RecipientPublicHex: strings.Repeat("33", 32),
			},
		},
		{
			name: "request with long filename",
			request: protocol.AgeUnwrapPayload{
				Type:               protocol.AgeUnwrapPayloadTypeAgeUnwrap,
				EphemeralPublicHex: strings.Repeat("44", 32),
				WrappedFileKey:     bytes.Repeat([]byte{0x55}, 32),
				RecipientPublicHex: strings.Repeat("66", 32),
				Display: &protocol.GenericDisplaySchema{
					Title: "Decrypt file?",
					Icon:  &icon,
					Fields: []protocol.DisplayField{
						{Label: "File", Value: "/very/long/path/to/some/deeply/nested/directory/with/encrypted/file.age"},
						{Label: "Size", Value: "104857600 bytes"},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.request)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}

			// Verify it can be unmarshaled back
			var decoded protocol.AgeUnwrapPayload
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("json.Unmarshal() error = %v", err)
			}

			// Verify fields match
			if decoded.Type != tt.request.Type {
				t.Errorf("Type = %v, want %v", decoded.Type, tt.request.Type)
			}

			if decoded.EphemeralPublicHex != tt.request.EphemeralPublicHex {
				t.Errorf("EphemeralPublicHex mismatch")
			}

			if !bytes.Equal(decoded.WrappedFileKey, tt.request.WrappedFileKey) {
				t.Errorf("WrappedFileKey mismatch")
			}

			if decoded.RecipientPublicHex != tt.request.RecipientPublicHex {
				t.Errorf("RecipientPublicHex mismatch")
			}

			// Verify Display schema round-trips
			if tt.request.Display != nil && decoded.Display != nil {
				if decoded.Display.Title != tt.request.Display.Title {
					t.Errorf("Display.Title = %v, want %v", decoded.Display.Title, tt.request.Display.Title)
				}
			}
		})
	}
}

func TestAgeUnwrapPayloadJSONFieldNames(t *testing.T) {
	icon := "lock.open"
	request := protocol.AgeUnwrapPayload{
		Type:               protocol.AgeUnwrapPayloadTypeAgeUnwrap,
		EphemeralPublicHex: hex.EncodeToString([]byte{0x01, 0x02}),
		WrappedFileKey:     []byte{0x03, 0x04},
		RecipientPublicHex: hex.EncodeToString([]byte{0x05, 0x06}),
		Display: &protocol.GenericDisplaySchema{
			Title: "Decrypt file?",
			Icon:  &icon,
			Fields: []protocol.DisplayField{
				{Label: "File", Value: "test.age"},
			},
		},
	}

	data, _ := json.Marshal(request)

	// Verify JSON field names match OpenAPI spec (camelCase)
	expectedFields := []string{
		`"type"`,
		`"ephemeralPublicHex"`,
		`"wrappedFileKey"`,
		`"recipientPublicHex"`,
		`"display"`,
		`"title"`,
		`"fields"`,
	}

	for _, field := range expectedFields {
		if !bytes.Contains(data, []byte(field)) {
			t.Errorf("JSON should contain field %s, got: %s", field, string(data))
		}
	}
}

func TestUnwrapResponseIsSuccess(t *testing.T) {
	tests := []struct {
		name     string
		response UnwrapResponse
		want     bool
	}{
		{
			name: "success with file key",
			response: UnwrapResponse{
				AgeUnwrapResponse: protocol.AgeUnwrapResponse{
					FileKey: ptrBytes(bytes.Repeat([]byte{0x42}, 16)),
				},
			},
			want: true,
		},
		{
			name: "error with code",
			response: UnwrapResponse{
				AgeUnwrapResponse: protocol.AgeUnwrapResponse{
					ErrorCode:    ptrErrorCode(1),
					ErrorMessage: ptrString("user declined"),
				},
			},
			want: false,
		},
		{
			name: "no file key returned",
			response: UnwrapResponse{
				AgeUnwrapResponse: protocol.AgeUnwrapResponse{
					FileKey: nil,
				},
			},
			want: false,
		},
		{
			name: "empty file key",
			response: UnwrapResponse{
				AgeUnwrapResponse: protocol.AgeUnwrapResponse{
					FileKey: ptrBytes([]byte{}),
				},
			},
			want: false,
		},
		{
			name: "error code with file key",
			response: UnwrapResponse{
				AgeUnwrapResponse: protocol.AgeUnwrapResponse{
					FileKey:      ptrBytes(bytes.Repeat([]byte{0x42}, 16)),
					ErrorCode:    ptrErrorCode(1), // Error code takes precedence
					ErrorMessage: ptrString("should not happen"),
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.response.IsSuccess(); got != tt.want {
				t.Errorf("IsSuccess() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUnwrapResponseError(t *testing.T) {
	tests := []struct {
		name        string
		response    UnwrapResponse
		wantNil     bool
		errContains string
	}{
		{
			name: "success returns nil",
			response: UnwrapResponse{
				AgeUnwrapResponse: protocol.AgeUnwrapResponse{
					FileKey: ptrBytes(bytes.Repeat([]byte{0x42}, 16)),
				},
			},
			wantNil: true,
		},
		{
			name: "error with code and message",
			response: UnwrapResponse{
				AgeUnwrapResponse: protocol.AgeUnwrapResponse{
					ErrorCode:    ptrErrorCode(42),
					ErrorMessage: ptrString("user declined the request"),
				},
			},
			wantNil:     false,
			errContains: "code 42",
		},
		{
			name: "error with code and message - contains message",
			response: UnwrapResponse{
				AgeUnwrapResponse: protocol.AgeUnwrapResponse{
					ErrorCode:    ptrErrorCode(42),
					ErrorMessage: ptrString("user declined the request"),
				},
			},
			wantNil:     false,
			errContains: "user declined",
		},
		{
			name: "no file key returns error",
			response: UnwrapResponse{
				AgeUnwrapResponse: protocol.AgeUnwrapResponse{
					FileKey: nil,
				},
			},
			wantNil:     false,
			errContains: "no file key",
		},
		{
			name: "error code zero",
			response: UnwrapResponse{
				AgeUnwrapResponse: protocol.AgeUnwrapResponse{
					ErrorCode:    ptrErrorCode(0),
					ErrorMessage: ptrString("unknown error"),
				},
			},
			wantNil:     false,
			errContains: "code 0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.response.Error()
			if tt.wantNil {
				if err != nil {
					t.Errorf("Error() = %v, want nil", err)
				}
				return
			}

			if err == nil {
				t.Error("Error() = nil, want error")
				return
			}

			if tt.errContains != "" && !bytes.Contains([]byte(err.Error()), []byte(tt.errContains)) {
				t.Errorf("Error() = %v, want error containing %v", err, tt.errContains)
			}
		})
	}
}

func TestUnwrapResponseMarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		response UnwrapResponse
	}{
		{
			name: "success response",
			response: UnwrapResponse{
				AgeUnwrapResponse: protocol.AgeUnwrapResponse{
					FileKey: ptrBytes(bytes.Repeat([]byte{0x42}, 16)),
				},
			},
		},
		{
			name: "error response",
			response: UnwrapResponse{
				AgeUnwrapResponse: protocol.AgeUnwrapResponse{
					ErrorCode:    ptrErrorCode(1),
					ErrorMessage: ptrString("test error"),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.response)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}

			var decoded UnwrapResponse
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("json.Unmarshal() error = %v", err)
			}

			// Verify roundtrip
			if tt.response.IsSuccess() != decoded.IsSuccess() {
				t.Errorf("roundtrip IsSuccess() = %v, want %v", decoded.IsSuccess(), tt.response.IsSuccess())
			}

			if !bytes.Equal(decoded.GetFileKey(), tt.response.GetFileKey()) {
				t.Errorf("roundtrip FileKey mismatch")
			}
		})
	}
}

func TestGenericDisplaySchemaMarshal(t *testing.T) {
	icon := "lock.open"
	display := protocol.GenericDisplaySchema{
		Title: "Decrypt file?",
		Icon:  &icon,
		Fields: []protocol.DisplayField{
			{Label: "File", Value: "test.age"},
			{Label: "Size", Value: "1024 bytes"},
		},
	}

	data, err := json.Marshal(display)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	jsonStr := string(data)
	expectedFields := []string{`"title"`, `"icon"`, `"fields"`, `"label"`, `"value"`}
	for _, field := range expectedFields {
		if !bytes.Contains(data, []byte(field)) {
			t.Errorf("JSON should contain field %s, got: %s", field, jsonStr)
		}
	}
}

func TestRequestTypeConstant(t *testing.T) {
	// Verify the constant matches what iOS expects
	if RequestTypeAgeUnwrap != "age_unwrap" {
		t.Errorf("RequestTypeAgeUnwrap = %v, want 'age_unwrap'", RequestTypeAgeUnwrap)
	}
}

func TestTruncateHex(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"short hex", "AABBCCDD", "AABBCCDD"},
		{"exactly 16 chars", "AABBCCDDAABBCCDD", "AABBCCDDAABBCCDD"},
		{"17 chars", "AABBCCDDAABBCCDDE", "AABBCCDD...ABBCCDDE"},
		{"40 char fingerprint", "AABBCCDDEEFF00112233445566778899AABBCCDD", "AABBCCDD...AABBCCDD"},
		{"empty string", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncateHex(tt.input)
			if got != tt.want {
				t.Errorf("truncateHex(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestUnwrapResponseGetFileKey(t *testing.T) {
	// nil FileKey
	r := &UnwrapResponse{}
	if got := r.GetFileKey(); got != nil {
		t.Errorf("GetFileKey() = %v, want nil", got)
	}

	// non-nil FileKey
	fileKey := []byte{0x01, 0x02, 0x03}
	r = &UnwrapResponse{
		AgeUnwrapResponse: protocol.AgeUnwrapResponse{
			FileKey: &fileKey,
		},
	}
	if got := r.GetFileKey(); !bytes.Equal(got, fileKey) {
		t.Errorf("GetFileKey() = %v, want %v", got, fileKey)
	}
}

func TestUnwrapResponseGetErrorCode(t *testing.T) {
	// nil ErrorCode
	r := &UnwrapResponse{}
	if got := r.GetErrorCode(); got != nil {
		t.Errorf("GetErrorCode() = %v, want nil", got)
	}

	// non-nil ErrorCode
	r = &UnwrapResponse{
		AgeUnwrapResponse: protocol.AgeUnwrapResponse{
			ErrorCode: ptrErrorCode(42),
		},
	}
	got := r.GetErrorCode()
	if got == nil {
		t.Fatal("GetErrorCode() = nil, want 42")
	}
	if *got != 42 {
		t.Errorf("GetErrorCode() = %d, want 42", *got)
	}
}

func TestUnwrapResponseGetErrorMessage(t *testing.T) {
	// nil ErrorMessage
	r := &UnwrapResponse{}
	if got := r.GetErrorMessage(); got != "" {
		t.Errorf("GetErrorMessage() = %q, want empty", got)
	}

	// non-nil ErrorMessage
	r = &UnwrapResponse{
		AgeUnwrapResponse: protocol.AgeUnwrapResponse{
			ErrorMessage: ptrString("something went wrong"),
		},
	}
	if got := r.GetErrorMessage(); got != "something went wrong" {
		t.Errorf("GetErrorMessage() = %q, want %q", got, "something went wrong")
	}
}

// Helper functions to create pointers for generated types

func ptrErrorCode(i int) *protocol.AckAgentCommonSigningErrorCode {
	code := protocol.AckAgentCommonSigningErrorCode(i)
	return &code
}

func ptrString(s string) *string {
	return &s
}

func ptrBytes(b []byte) *[]byte {
	return &b
}
