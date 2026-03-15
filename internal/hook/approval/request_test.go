package approval

import (
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
)

func TestSerializeContextPreimage(t *testing.T) {
	tests := []struct {
		name    string
		ctx     *ApprovalContext
		wantErr bool
	}{
		{
			name: "valid context",
			ctx: &ApprovalContext{
				SessionID: "session-123",
				ToolName:  "Bash",
				ToolInput: map[string]any{"command": "ls -la"},
				Timestamp: 1703001234567,
			},
			wantErr: false,
		},
		{
			name: "minimal context",
			ctx: &ApprovalContext{
				SessionID: "abc",
				ToolName:  "Write",
				Timestamp: 0,
			},
			wantErr: false,
		},
		{
			name: "context with nested input",
			ctx: &ApprovalContext{
				SessionID: "session-456",
				ToolName:  "MultiEdit",
				ToolInput: map[string]any{
					"files": []any{
						map[string]any{"path": "/tmp/a.txt", "content": "a"},
						map[string]any{"path": "/tmp/b.txt", "content": "b"},
					},
				},
				Timestamp: 1703001234567,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			preimage, err := SerializeContextPreimage(tt.ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("SerializeContextPreimage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				// Preimage should be valid JSON
				if !json.Valid(preimage) {
					t.Errorf("SerializeContextPreimage() returned invalid JSON: %s", preimage)
				}
				// Preimage should be non-empty
				if len(preimage) == 0 {
					t.Error("SerializeContextPreimage() returned empty bytes")
				}
			}
		})
	}
}

func TestSerializeContextPreimage_Deterministic(t *testing.T) {
	ctx := &ApprovalContext{
		SessionID: "test-session",
		ToolName:  "Bash",
		ToolInput: map[string]any{"command": "echo hello"},
		Timestamp: 1703001234567,
	}

	preimage1, err := SerializeContextPreimage(ctx)
	if err != nil {
		t.Fatalf("First SerializeContextPreimage() error = %v", err)
	}

	preimage2, err := SerializeContextPreimage(ctx)
	if err != nil {
		t.Fatalf("Second SerializeContextPreimage() error = %v", err)
	}

	if string(preimage1) != string(preimage2) {
		t.Errorf("SerializeContextPreimage() not deterministic: %s != %s", preimage1, preimage2)
	}
}

func TestSerializeContextPreimage_DifferentInputsProduceDifferentPreimages(t *testing.T) {
	ctx1 := &ApprovalContext{
		SessionID: "session-1",
		ToolName:  "Bash",
		ToolInput: map[string]any{"command": "ls"},
		Timestamp: 1000,
	}
	ctx2 := &ApprovalContext{
		SessionID: "session-2",
		ToolName:  "Bash",
		ToolInput: map[string]any{"command": "ls"},
		Timestamp: 1000,
	}

	preimage1, _ := SerializeContextPreimage(ctx1)
	preimage2, _ := SerializeContextPreimage(ctx2)

	if string(preimage1) == string(preimage2) {
		t.Error("Different sessions should produce different preimages")
	}

	// Different commands
	ctx3 := &ApprovalContext{
		SessionID: "session-1",
		ToolName:  "Bash",
		ToolInput: map[string]any{"command": "pwd"},
		Timestamp: 1000,
	}
	preimage3, _ := SerializeContextPreimage(ctx3)
	if string(preimage1) == string(preimage3) {
		t.Error("Different commands should produce different preimages")
	}

	// Different timestamps
	ctx4 := &ApprovalContext{
		SessionID: "session-1",
		ToolName:  "Bash",
		ToolInput: map[string]any{"command": "ls"},
		Timestamp: 2000,
	}
	preimage4, _ := SerializeContextPreimage(ctx4)
	if string(preimage1) == string(preimage4) {
		t.Error("Different timestamps should produce different preimages")
	}
}

func TestShouldAllowModification(t *testing.T) {
	tests := []struct {
		toolName string
		want     bool
	}{
		{"Bash", true},
		{"Write", false},
		{"Edit", false},
		{"MultiEdit", false},
		{"Read", false},
		{"Unknown", false},
	}

	for _, tt := range tests {
		t.Run(tt.toolName, func(t *testing.T) {
			got := shouldAllowModification(tt.toolName)
			if got != tt.want {
				t.Errorf("shouldAllowModification(%q) = %v, want %v", tt.toolName, got, tt.want)
			}
		})
	}
}

func TestGetActionTitle(t *testing.T) {
	tests := []struct {
		toolName string
		want     string
	}{
		{"Bash", "Allow command?"},
		{"Write", "Allow file write?"},
		{"Edit", "Allow file edit?"},
		{"MultiEdit", "Allow file edits?"},
		{"Unknown", "Allow action?"},
		{"Read", "Allow action?"},
	}

	for _, tt := range tests {
		t.Run(tt.toolName, func(t *testing.T) {
			got := getActionTitle(tt.toolName)
			if got != tt.want {
				t.Errorf("getActionTitle(%q) = %v, want %v", tt.toolName, got, tt.want)
			}
		})
	}
}

func TestFormatToolInput(t *testing.T) {
	tests := []struct {
		name      string
		toolName  string
		toolInput map[string]any
		want      string
		maxLen    int
	}{
		{
			name:      "bash command",
			toolName:  "Bash",
			toolInput: map[string]any{"command": "ls -la"},
			want:      "ls -la",
		},
		{
			name:      "write file path",
			toolName:  "Write",
			toolInput: map[string]any{"file_path": "/tmp/test.txt"},
			want:      "/tmp/test.txt",
		},
		{
			name:      "edit file path",
			toolName:  "Edit",
			toolInput: map[string]any{"file_path": "/home/user/file.go"},
			want:      "/home/user/file.go",
		},
		{
			name:      "nil input",
			toolName:  "Bash",
			toolInput: nil,
			want:      "",
		},
		{
			name:      "long command truncated",
			toolName:  "Bash",
			toolInput: map[string]any{"command": strings.Repeat("a", 300)},
			maxLen:    204, // 200 + "..."
		},
		{
			name:      "unknown tool uses json",
			toolName:  "Custom",
			toolInput: map[string]any{"key": "value"},
			want:      `{"key":"value"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatToolInput(tt.toolName, tt.toolInput)
			if tt.want != "" && got != tt.want {
				t.Errorf("formatToolInput(%q, %v) = %v, want %v", tt.toolName, tt.toolInput, got, tt.want)
			}
			if tt.maxLen > 0 && len(got) > tt.maxLen {
				t.Errorf("formatToolInput() length = %d, want <= %d", len(got), tt.maxLen)
			}
		})
	}
}

// Regression: preimage must be raw JSON bytes, not a hex hash string.
func TestSerializeContextPreimage_ReturnsRawJSONNotHash(t *testing.T) {
	ctx := &ApprovalContext{
		SessionID: "session-123",
		ToolName:  "Bash",
		ToolInput: map[string]any{"command": "ls -la"},
		Timestamp: 1703001234567,
	}

	preimage, err := SerializeContextPreimage(ctx)
	if err != nil {
		t.Fatalf("SerializeContextPreimage() error = %v", err)
	}

	// Must be valid JSON
	if !json.Valid(preimage) {
		t.Fatalf("preimage is not valid JSON: %s", preimage)
	}

	// Must NOT be a hex hash string (old format was "sha256:<hex>")
	if strings.HasPrefix(string(preimage), "sha256:") {
		t.Error("preimage must be raw JSON bytes, not a hex hash string")
	}

	// Must round-trip back to the original context
	var roundTripped ApprovalContext
	if err := json.Unmarshal(preimage, &roundTripped); err != nil {
		t.Fatalf("failed to unmarshal preimage: %v", err)
	}
	if roundTripped.SessionID != ctx.SessionID {
		t.Errorf("SessionID mismatch: got %s, want %s", roundTripped.SessionID, ctx.SessionID)
	}
	if roundTripped.ToolName != ctx.ToolName {
		t.Errorf("ToolName mismatch: got %s, want %s", roundTripped.ToolName, ctx.ToolName)
	}
	if roundTripped.Timestamp != ctx.Timestamp {
		t.Errorf("Timestamp mismatch: got %d, want %d", roundTripped.Timestamp, ctx.Timestamp)
	}
}

// Regression: SHA256 of preimage should be a stable 32-byte digest.
func TestSerializeContextPreimage_SHA256DigestIs32Bytes(t *testing.T) {
	ctx := &ApprovalContext{
		SessionID: "session-123",
		ToolName:  "Bash",
		ToolInput: map[string]any{"command": "echo hello"},
		Timestamp: 1703001234567,
	}

	preimage, err := SerializeContextPreimage(ctx)
	if err != nil {
		t.Fatalf("SerializeContextPreimage() error = %v", err)
	}

	digest := sha256.Sum256(preimage)
	if len(digest) != 32 {
		t.Errorf("SHA256 digest length = %d, want 32", len(digest))
	}

	// Digest must be deterministic
	digest2 := sha256.Sum256(preimage)
	if digest != digest2 {
		t.Error("SHA256 digest is not deterministic")
	}
}
