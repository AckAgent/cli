// Package claude handles Claude Code hook integration.
package claude

import (
	"encoding/json"
	"fmt"
	"io"

	protocol "github.com/ackagent/api/go/protocol"
)

// HookInput is the JSON received from Claude Code on stdin.
// See: https://code.claude.com/docs/en/hooks
type HookInput struct {
	SessionID      string         `json:"session_id"`
	HookEventName  string         `json:"hook_event_name"`
	ToolName       string         `json:"tool_name,omitempty"`
	ToolInput      map[string]any `json:"tool_input,omitempty"`
	ToolUseID      string         `json:"tool_use_id,omitempty"`
	TranscriptPath string         `json:"transcript_path,omitempty"`
	Cwd            string         `json:"cwd,omitempty"`
	PermissionMode string         `json:"permission_mode,omitempty"`
}

// ReadInput reads and parses the hook input from the given reader.
func ReadInput(r io.Reader) (*HookInput, error) {
	var input HookInput
	decoder := json.NewDecoder(r)
	if err := decoder.Decode(&input); err != nil {
		return nil, fmt.Errorf("failed to parse hook input: %w", err)
	}
	return &input, nil
}

// Validate checks that the input has required fields for processing.
func (h *HookInput) Validate() error {
	if h.HookEventName == "" {
		return fmt.Errorf("missing hook_event_name")
	}
	if h.SessionID == "" {
		return fmt.Errorf("missing session_id")
	}
	return nil
}

// IsPermissionRequest returns true if this is a PermissionRequest hook event.
func (h *HookInput) IsPermissionRequest() bool {
	return h.HookEventName == "PermissionRequest"
}

// IsPreToolUse returns true if this is a PreToolUse hook event.
func (h *HookInput) IsPreToolUse() bool {
	return h.HookEventName == "PreToolUse"
}

// IsAskUserQuestion returns true if the tool being called is AskUserQuestion.
func (h *HookInput) IsAskUserQuestion() bool {
	return h.ToolName == "AskUserQuestion"
}

// GetQuestions extracts questions from the AskUserQuestion tool input.
// Returns questions using the generated protocol types.
func (h *HookInput) GetQuestions() ([]protocol.ClaudeQuestion, error) {
	if h.ToolInput == nil {
		return nil, fmt.Errorf("no tool input")
	}

	questionsRaw, ok := h.ToolInput["questions"]
	if !ok {
		return nil, fmt.Errorf("no questions field in tool input")
	}

	// Convert through JSON to properly unmarshal the nested structure
	data, err := json.Marshal(questionsRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal questions: %w", err)
	}

	var questions []protocol.ClaudeQuestion
	if err := json.Unmarshal(data, &questions); err != nil {
		return nil, fmt.Errorf("failed to unmarshal questions: %w", err)
	}

	return questions, nil
}

// GetCommand returns the command string if this is a Bash tool call.
func (h *HookInput) GetCommand() string {
	if h.ToolInput == nil {
		return ""
	}
	if cmd, ok := h.ToolInput["command"].(string); ok {
		return cmd
	}
	return ""
}

// GetFilePath returns the file path if this is a Write/Edit tool call.
func (h *HookInput) GetFilePath() string {
	if h.ToolInput == nil {
		return ""
	}
	if path, ok := h.ToolInput["file_path"].(string); ok {
		return path
	}
	return ""
}

// FormatToolInput returns a human-readable summary of the tool input.
func (h *HookInput) FormatToolInput() string {
	switch h.ToolName {
	case "Bash":
		if cmd := h.GetCommand(); cmd != "" {
			if len(cmd) > 200 {
				return cmd[:200] + "..."
			}
			return cmd
		}
	case "Write", "Edit", "MultiEdit":
		if path := h.GetFilePath(); path != "" {
			return path
		}
	}
	// Fallback: JSON representation
	data, _ := json.Marshal(h.ToolInput)
	s := string(data)
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}
