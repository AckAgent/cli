// Package approval handles sending approval requests to iOS and processing responses.
package approval

import (
	"context"
	"encoding/json"
	"fmt"

	protocol "github.com/ackagent/api/go/protocol"
	"github.com/ackagent/cli/internal/shared/config"
	"github.com/ackagent/cli/internal/shared/sysinfo"
	"github.com/ackagent/cli/internal/shared/transport"
)

// ApprovalContext contains the data that will be signed to verify the approval.
// This is a CLI internal type used for context hash computation.
type ApprovalContext struct {
	SessionID string         `json:"session_id"`
	ToolName  string         `json:"tool_name"`
	ToolInput map[string]any `json:"tool_input"`
	Timestamp int64          `json:"timestamp"`
}

// ApprovalResult is the result of an approval request.
// This is a CLI internal type for processing the decrypted response.
type ApprovalResult struct {
	Approved     bool
	AlwaysAllow  bool
	UpdatedInput map[string]any
	Message      string
	RuleID       string
	RulePattern  string
}

// QuestionContext contains the data for a question answering request.
// This is a CLI internal type.
type QuestionContext struct {
	SessionID string                    `json:"session_id"`
	Questions []protocol.ClaudeQuestion `json:"questions"`
	Timestamp int64                     `json:"timestamp"`
}

// QuestionResult is the result of a question answering request.
// This is a CLI internal type for processing the decrypted response.
type QuestionResult struct {
	Answered bool
	Answers  map[string]string // question_id -> option_id
	Message  string
}

// RequestApproval sends an approval request to the iOS device and waits for a response.
func RequestApproval(ctx context.Context, cfg *config.Config, approvalCtx *ApprovalContext) (*ApprovalResult, error) {
	if !cfg.IsLoggedIn() {
		return nil, fmt.Errorf("not logged in: please run 'ackagent login' first")
	}

	// Serialize context preimage (canonical JSON bytes)
	contextPreimage, err := SerializeContextPreimage(approvalCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize context preimage: %w", err)
	}

	// Build approval payload using generated protocol type
	allowsModification := shouldAllowModification(approvalCtx.ToolName)
	actionTitle := getActionTitle(approvalCtx.ToolName)
	actionDescription := formatToolInput(approvalCtx.ToolName, approvalCtx.ToolInput)

	// Get process info for source context
	processInfo := sysinfo.GetProcessInfo()

	title := "Claude Code"
	payload := &protocol.ClaudeApprovalPayload{
		Type:               protocol.ClaudeApproval,
		ToolName:           approvalCtx.ToolName,
		ToolInputFormatted: formatToolInput(approvalCtx.ToolName, approvalCtx.ToolInput),
		AllowsModification: &allowsModification,
		SessionId:          &approvalCtx.SessionID,
		ContextPreimage:    &contextPreimage,
		ActionTitle:        &actionTitle,
		ActionDescription:  &actionDescription,
		SourceInfo:         processInfo.ToSourceInfo(),
		Display: &protocol.GenericDisplaySchema{
			Title:  title,
			Fields: []protocol.DisplayField{},
		},
	}

	result, err := transport.NewRequestBuilder(cfg).
		WithTimestamp(approvalCtx.Timestamp).
		WithTimeout(config.DefaultSigningTimeout).
		WithExpiration(120).
		Send(ctx, payload)
	if err != nil {
		return nil, fmt.Errorf("waiting for response failed: %w", err)
	}

	// Privacy: Backend only knows "responded" - not approved or rejected
	// We must decrypt the response to determine the actual decision
	switch result.Response.Status {
	case "expired":
		return nil, fmt.Errorf("request expired")
	case "responded":
		// Continue to decrypt and process response to learn decision
	default:
		return nil, fmt.Errorf("unexpected status: %s", result.Response.Status)
	}

	// Decrypt and process response (decision is E2E encrypted)
	return processApprovalResponse(
		result.Response,
		result.EphemeralPrivate,
		result.RequestID,
		result.RequestIDString,
		contextPreimage,
		cfg,
	)
}

// SerializeContextPreimage returns the canonical JSON bytes of the approval context.
// The caller sends these bytes as the context preimage; the approver computes
// SHA-256 of this preimage and signs the resulting digest.
func SerializeContextPreimage(ctx *ApprovalContext) ([]byte, error) {
	return json.Marshal(ctx)
}

// shouldAllowModification returns true if the tool input can be modified by the user.
func shouldAllowModification(toolName string) bool {
	switch toolName {
	case "Bash":
		return true // Allow editing commands
	case "Write", "Edit":
		return false // Don't allow editing file content through this UI
	default:
		return false
	}
}

// getActionTitle returns an action-oriented title for the tool.
func getActionTitle(toolName string) string {
	switch toolName {
	case "Bash":
		return "Allow command?"
	case "Write":
		return "Allow file write?"
	case "Edit":
		return "Allow file edit?"
	case "MultiEdit":
		return "Allow file edits?"
	default:
		return "Allow action?"
	}
}

// formatToolInput returns a human-readable summary of the tool input.
func formatToolInput(toolName string, toolInput map[string]any) string {
	if toolInput == nil {
		return ""
	}

	switch toolName {
	case "Bash":
		if cmd, ok := toolInput["command"].(string); ok {
			if len(cmd) > 200 {
				return cmd[:200] + "..."
			}
			return cmd
		}
	case "Write", "Edit", "MultiEdit":
		if path, ok := toolInput["file_path"].(string); ok {
			return path
		}
	}

	// Fallback
	data, _ := json.Marshal(toolInput)
	s := string(data)
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}

// RequestQuestionAnswers sends a question request to the iOS device and waits for answers.
func RequestQuestionAnswers(ctx context.Context, cfg *config.Config, qCtx *QuestionContext) (*QuestionResult, error) {
	if !cfg.IsLoggedIn() {
		return nil, fmt.Errorf("not logged in: please run 'ackagent login' first")
	}

	// Build question payload using generated protocol type
	questionSummary := formatQuestionSummary(qCtx.Questions)

	// Get process info for source context
	processInfo := sysinfo.GetProcessInfo()

	questionTitle := "Answer Questions"
	payload := &protocol.ClaudeQuestionPayload{
		Type:       protocol.ClaudeQuestionPayloadTypeClaudeQuestion,
		Questions:  qCtx.Questions,
		SessionId:  &qCtx.SessionID,
		SourceInfo: processInfo.ToSourceInfo(),
		Display: &protocol.GenericDisplaySchema{
			Title:    questionTitle,
			Subtitle: &questionSummary,
			Fields:   []protocol.DisplayField{},
		},
	}

	result, err := transport.NewRequestBuilder(cfg).
		WithTimestamp(qCtx.Timestamp).
		WithTimeout(config.DefaultSigningTimeout).
		WithExpiration(120).
		Send(ctx, payload)
	if err != nil {
		return nil, fmt.Errorf("waiting for response failed: %w", err)
	}

	// Process response status
	switch result.Response.Status {
	case "expired":
		return nil, fmt.Errorf("request expired")
	case "responded":
		// Continue to decrypt and process response
	default:
		return nil, fmt.Errorf("unexpected status: %s", result.Response.Status)
	}

	// Decrypt and process response
	return processQuestionResponse(
		result.Response,
		result.EphemeralPrivate,
		result.RequestID,
		result.RequestIDString,
		cfg,
	)
}

// formatQuestionSummary creates a human-readable summary of the questions.
func formatQuestionSummary(questions []protocol.ClaudeQuestion) string {
	if len(questions) == 0 {
		return "No questions"
	}
	if len(questions) == 1 {
		q := questions[0].Question
		if len(q) > 100 {
			return q[:100] + "..."
		}
		return q
	}
	return fmt.Sprintf("%d questions from Claude", len(questions))
}
