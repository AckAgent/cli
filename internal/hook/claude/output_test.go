package claude

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestWriteOutput(t *testing.T) {
	tests := []struct {
		name   string
		output *HookOutput
		check  func(map[string]any) bool
	}{
		{
			name:   "allow output",
			output: AllowOutput("Approved via iOS"),
			check: func(m map[string]any) bool {
				hso, ok := m["hookSpecificOutput"].(map[string]any)
				if !ok {
					return false
				}
				decision, ok := hso["decision"].(map[string]any)
				if !ok {
					return false
				}
				return decision["behavior"] == "allow" &&
					decision["message"] == "Approved via iOS"
			},
		},
		{
			name:   "deny output",
			output: DenyOutput("Rejected by user"),
			check: func(m map[string]any) bool {
				if m["decision"] != "block" {
					return false
				}
				if m["reason"] != "Rejected by user" {
					return false
				}
				hso, ok := m["hookSpecificOutput"].(map[string]any)
				if !ok {
					return false
				}
				decision, ok := hso["decision"].(map[string]any)
				if !ok {
					return false
				}
				return decision["behavior"] == "deny"
			},
		},
		{
			name:   "passthrough output",
			output: PassthroughOutput(),
			check: func(m map[string]any) bool {
				// Should be empty or minimal
				return m["decision"] == nil && m["hookSpecificOutput"] == nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := WriteOutput(&buf, tt.output)
			if err != nil {
				t.Fatalf("WriteOutput() error = %v", err)
			}

			var result map[string]any
			if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
				t.Fatalf("Failed to unmarshal output: %v", err)
			}

			if !tt.check(result) {
				t.Errorf("WriteOutput() check failed, got: %s", buf.String())
			}
		})
	}
}

func TestAllowOutput(t *testing.T) {
	output := AllowOutput("test message")

	if output.Decision != nil {
		t.Error("AllowOutput should not set top-level decision")
	}
	if output.HookSpecificOutput == nil {
		t.Fatal("AllowOutput should set HookSpecificOutput")
	}
	if output.HookSpecificOutput.HookEventName != "PermissionRequest" {
		t.Errorf("HookEventName = %v, want PermissionRequest", output.HookSpecificOutput.HookEventName)
	}
	if output.HookSpecificOutput.Decision == nil {
		t.Fatal("AllowOutput should set Decision")
	}
	if output.HookSpecificOutput.Decision.Behavior != "allow" {
		t.Errorf("Behavior = %v, want allow", output.HookSpecificOutput.Decision.Behavior)
	}
	if output.HookSpecificOutput.Decision.Message != "test message" {
		t.Errorf("Message = %v, want test message", output.HookSpecificOutput.Decision.Message)
	}
}

func TestAllowWithUpdatedInput(t *testing.T) {
	updatedInput := map[string]any{"command": "ls -la --color"}
	output := AllowWithUpdatedInput("modified", updatedInput)

	if output.HookSpecificOutput == nil || output.HookSpecificOutput.Decision == nil {
		t.Fatal("AllowWithUpdatedInput should set HookSpecificOutput and Decision")
	}
	if output.HookSpecificOutput.Decision.Behavior != "allow" {
		t.Errorf("Behavior = %v, want allow", output.HookSpecificOutput.Decision.Behavior)
	}
	if output.HookSpecificOutput.Decision.UpdatedInput == nil {
		t.Fatal("UpdatedInput should be set")
	}
	if output.HookSpecificOutput.Decision.UpdatedInput["command"] != "ls -la --color" {
		t.Errorf("UpdatedInput command = %v, want ls -la --color", output.HookSpecificOutput.Decision.UpdatedInput["command"])
	}
}

func TestDenyOutput(t *testing.T) {
	output := DenyOutput("access denied")

	if output.Decision == nil || *output.Decision != "block" {
		t.Error("DenyOutput should set decision to 'block'")
	}
	if output.Reason != "access denied" {
		t.Errorf("Reason = %v, want 'access denied'", output.Reason)
	}
	if output.HookSpecificOutput == nil || output.HookSpecificOutput.Decision == nil {
		t.Fatal("DenyOutput should set HookSpecificOutput and Decision")
	}
	if output.HookSpecificOutput.Decision.Behavior != "deny" {
		t.Errorf("Behavior = %v, want deny", output.HookSpecificOutput.Decision.Behavior)
	}
}

func TestPassthroughOutput(t *testing.T) {
	output := PassthroughOutput()

	if output.Decision != nil {
		t.Error("PassthroughOutput should not set decision")
	}
	if output.Reason != "" {
		t.Error("PassthroughOutput should not set reason")
	}
	if output.HookSpecificOutput != nil {
		t.Error("PassthroughOutput should not set hookSpecificOutput")
	}
}

func TestApprovalResult_ToHookOutput(t *testing.T) {
	tests := []struct {
		name   string
		result ApprovalResult
		check  func(*HookOutput) bool
	}{
		{
			name: "approved without updated input",
			result: ApprovalResult{
				Approved: true,
				Message:  "approved",
			},
			check: func(h *HookOutput) bool {
				return h.Decision == nil &&
					h.HookSpecificOutput.Decision.Behavior == "allow" &&
					h.HookSpecificOutput.Decision.UpdatedInput == nil
			},
		},
		{
			name: "approved with updated input",
			result: ApprovalResult{
				Approved:     true,
				UpdatedInput: map[string]any{"command": "new command"},
				Message:      "modified",
			},
			check: func(h *HookOutput) bool {
				return h.HookSpecificOutput.Decision.Behavior == "allow" &&
					h.HookSpecificOutput.Decision.UpdatedInput != nil &&
					h.HookSpecificOutput.Decision.UpdatedInput["command"] == "new command"
			},
		},
		{
			name: "rejected",
			result: ApprovalResult{
				Approved: false,
				Message:  "rejected by user",
			},
			check: func(h *HookOutput) bool {
				return h.Decision != nil && *h.Decision == "block" &&
					h.HookSpecificOutput.Decision.Behavior == "deny"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.result.ToHookOutput()
			if !tt.check(got) {
				t.Errorf("ToHookOutput() check failed")
			}
		})
	}
}

func TestFormatError(t *testing.T) {
	err := FormatError(nil)
	if err != "ackagent hook: <nil>" {
		t.Errorf("FormatError(nil) = %v", err)
	}

	var dummy interface{}
	err = FormatError(json.Unmarshal([]byte("bad"), &dummy))
	if err == "" {
		t.Error("FormatError should return non-empty string")
	}
}
