package claude

import (
	"strings"
	"testing"
)

func TestReadInput(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		check   func(*HookInput) bool
	}{
		{
			name: "valid permission request",
			input: `{
				"session_id": "test-session-123",
				"hook_event_name": "PermissionRequest",
				"tool_name": "Bash",
				"tool_input": {"command": "ls -la"},
				"cwd": "/home/user"
			}`,
			wantErr: false,
			check: func(h *HookInput) bool {
				return h.SessionID == "test-session-123" &&
					h.HookEventName == "PermissionRequest" &&
					h.ToolName == "Bash" &&
					h.GetCommand() == "ls -la"
			},
		},
		{
			name: "valid write tool request",
			input: `{
				"session_id": "test-session-456",
				"hook_event_name": "PermissionRequest",
				"tool_name": "Write",
				"tool_input": {"file_path": "/tmp/test.txt", "content": "hello"}
			}`,
			wantErr: false,
			check: func(h *HookInput) bool {
				return h.ToolName == "Write" &&
					h.GetFilePath() == "/tmp/test.txt"
			},
		},
		{
			name:    "empty input",
			input:   "",
			wantErr: true,
		},
		{
			name:    "invalid json",
			input:   "not json",
			wantErr: true,
		},
		{
			name: "minimal valid input",
			input: `{
				"session_id": "abc",
				"hook_event_name": "PermissionRequest"
			}`,
			wantErr: false,
			check: func(h *HookInput) bool {
				return h.SessionID == "abc" && h.HookEventName == "PermissionRequest"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := strings.NewReader(tt.input)
			got, err := ReadInput(reader)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadInput() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.check != nil && !tt.check(got) {
				t.Errorf("ReadInput() check failed, got %+v", got)
			}
		})
	}
}

func TestHookInput_Validate(t *testing.T) {
	tests := []struct {
		name    string
		input   HookInput
		wantErr bool
	}{
		{
			name: "valid input",
			input: HookInput{
				SessionID:     "session-123",
				HookEventName: "PermissionRequest",
			},
			wantErr: false,
		},
		{
			name: "missing session_id",
			input: HookInput{
				HookEventName: "PermissionRequest",
			},
			wantErr: true,
		},
		{
			name: "missing hook_event_name",
			input: HookInput{
				SessionID: "session-123",
			},
			wantErr: true,
		},
		{
			name:    "empty input",
			input:   HookInput{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.input.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestHookInput_IsPermissionRequest(t *testing.T) {
	tests := []struct {
		name          string
		hookEventName string
		want          bool
	}{
		{"permission request", "PermissionRequest", true},
		{"stop event", "Stop", false},
		{"empty", "", false},
		{"other event", "SomeOther", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &HookInput{HookEventName: tt.hookEventName}
			if got := h.IsPermissionRequest(); got != tt.want {
				t.Errorf("IsPermissionRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHookInput_GetCommand(t *testing.T) {
	tests := []struct {
		name      string
		toolInput map[string]any
		want      string
	}{
		{
			name:      "bash command",
			toolInput: map[string]any{"command": "ls -la"},
			want:      "ls -la",
		},
		{
			name:      "nil input",
			toolInput: nil,
			want:      "",
		},
		{
			name:      "no command key",
			toolInput: map[string]any{"other": "value"},
			want:      "",
		},
		{
			name:      "command not string",
			toolInput: map[string]any{"command": 123},
			want:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &HookInput{ToolInput: tt.toolInput}
			if got := h.GetCommand(); got != tt.want {
				t.Errorf("GetCommand() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHookInput_GetFilePath(t *testing.T) {
	tests := []struct {
		name      string
		toolInput map[string]any
		want      string
	}{
		{
			name:      "file path present",
			toolInput: map[string]any{"file_path": "/tmp/test.txt"},
			want:      "/tmp/test.txt",
		},
		{
			name:      "nil input",
			toolInput: nil,
			want:      "",
		},
		{
			name:      "no file_path key",
			toolInput: map[string]any{"command": "ls"},
			want:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &HookInput{ToolInput: tt.toolInput}
			if got := h.GetFilePath(); got != tt.want {
				t.Errorf("GetFilePath() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHookInput_FormatToolInput(t *testing.T) {
	tests := []struct {
		name      string
		toolName  string
		toolInput map[string]any
		wantLen   int // expected max length, 0 to skip check
		contains  string
	}{
		{
			name:      "bash command",
			toolName:  "Bash",
			toolInput: map[string]any{"command": "ls -la"},
			contains:  "ls -la",
		},
		{
			name:      "write file path",
			toolName:  "Write",
			toolInput: map[string]any{"file_path": "/tmp/test.txt"},
			contains:  "/tmp/test.txt",
		},
		{
			name:      "long command truncated",
			toolName:  "Bash",
			toolInput: map[string]any{"command": strings.Repeat("a", 250)},
			wantLen:   204, // 200 + "..."
		},
		{
			name:      "unknown tool uses json",
			toolName:  "Unknown",
			toolInput: map[string]any{"key": "value"},
			contains:  "key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &HookInput{
				ToolName:  tt.toolName,
				ToolInput: tt.toolInput,
			}
			got := h.FormatToolInput()
			if tt.wantLen > 0 && len(got) > tt.wantLen {
				t.Errorf("FormatToolInput() length = %d, want <= %d", len(got), tt.wantLen)
			}
			if tt.contains != "" && !strings.Contains(got, tt.contains) {
				t.Errorf("FormatToolInput() = %v, want contains %v", got, tt.contains)
			}
		})
	}
}
