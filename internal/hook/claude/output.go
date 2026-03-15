package claude

import (
	"encoding/json"
	"fmt"
	"io"
)

// HookOutput is the JSON written to stdout for Claude Code.
type HookOutput struct {
	// Decision can be "block" to block the action, or omitted to allow
	Decision *string `json:"decision,omitempty"`

	// Reason is shown when the action is blocked
	Reason string `json:"reason,omitempty"`

	// HookSpecificOutput contains event-specific control fields
	HookSpecificOutput *HookSpecificOutput `json:"hookSpecificOutput,omitempty"`
}

// HookSpecificOutput contains event-specific control fields.
type HookSpecificOutput struct {
	HookEventName string `json:"hookEventName"`

	// For PermissionRequest events
	Decision *PermissionDecision `json:"decision,omitempty"`

	// For PreToolUse events
	PermissionDecision string         `json:"permissionDecision,omitempty"` // "allow" or "deny"
	UpdatedInput       map[string]any `json:"updatedInput,omitempty"`       // Modified tool input (e.g., answers)
}

// PermissionDecision controls the permission decision for PermissionRequest events.
type PermissionDecision struct {
	// Behavior is "allow" or "deny"
	Behavior string `json:"behavior"`

	// UpdatedInput optionally modifies the tool input before execution
	UpdatedInput map[string]any `json:"updatedInput,omitempty"`

	// Message is shown to the user (e.g., why denied)
	Message string `json:"message,omitempty"`

	// Interrupt stops Claude if denied (default: false)
	Interrupt bool `json:"interrupt,omitempty"`
}

// WriteOutput writes the hook output as JSON to the given writer.
func WriteOutput(w io.Writer, output *HookOutput) error {
	encoder := json.NewEncoder(w)
	return encoder.Encode(output)
}

// AllowOutput creates a HookOutput that allows the action.
func AllowOutput(message string) *HookOutput {
	return &HookOutput{
		HookSpecificOutput: &HookSpecificOutput{
			HookEventName: "PermissionRequest",
			Decision: &PermissionDecision{
				Behavior: "allow",
				Message:  message,
			},
		},
	}
}

// AllowWithUpdatedInput creates a HookOutput that allows the action with modified input.
func AllowWithUpdatedInput(message string, updatedInput map[string]any) *HookOutput {
	return &HookOutput{
		HookSpecificOutput: &HookSpecificOutput{
			HookEventName: "PermissionRequest",
			Decision: &PermissionDecision{
				Behavior:     "allow",
				Message:      message,
				UpdatedInput: updatedInput,
			},
		},
	}
}

// DenyOutput creates a HookOutput that denies the action.
func DenyOutput(message string) *HookOutput {
	block := "block"
	return &HookOutput{
		Decision: &block,
		Reason:   message,
		HookSpecificOutput: &HookSpecificOutput{
			HookEventName: "PermissionRequest",
			Decision: &PermissionDecision{
				Behavior: "deny",
				Message:  message,
			},
		},
	}
}

// PassthroughOutput creates an empty output that passes through to default behavior.
// This is used when the hook doesn't want to interfere (e.g., not paired).
func PassthroughOutput() *HookOutput {
	return &HookOutput{}
}

// OutputResult writes the appropriate response based on the approval result.
type ApprovalResult struct {
	Approved     bool
	AlwaysAllow  bool
	UpdatedInput map[string]any
	Message      string
}

// ToHookOutput converts an ApprovalResult to a HookOutput.
func (r *ApprovalResult) ToHookOutput() *HookOutput {
	if r.Approved {
		if len(r.UpdatedInput) > 0 {
			return AllowWithUpdatedInput(r.Message, r.UpdatedInput)
		}
		return AllowOutput(r.Message)
	}
	return DenyOutput(r.Message)
}

// FormatError formats an error for output to stderr.
func FormatError(err error) string {
	return fmt.Sprintf("ackagent hook: %v", err)
}

// QuestionResult contains the result of a question answering request.
type QuestionResult struct {
	Answered bool
	Answers  map[string]string // question_id -> option_id
	Message  string
}

// ToHookOutput converts a QuestionResult to a HookOutput for PreToolUse.
func (r *QuestionResult) ToHookOutput() *HookOutput {
	if !r.Answered {
		// Fall back to local prompting
		return PassthroughOutput()
	}

	// Convert answers to the format expected by AskUserQuestion
	answers := make(map[string]any)
	for k, v := range r.Answers {
		answers[k] = v
	}

	return &HookOutput{
		HookSpecificOutput: &HookSpecificOutput{
			HookEventName:      "PreToolUse",
			PermissionDecision: "allow",
			UpdatedInput: map[string]any{
				"answers": answers,
			},
		},
	}
}
