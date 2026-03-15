package approval

import (
	"strings"
	"testing"

	protocol "github.com/ackagent/api/go/protocol"
)

func TestFormatQuestionSummary(t *testing.T) {
	tests := []struct {
		name      string
		questions []protocol.ClaudeQuestion
		want      string
	}{
		{
			name:      "empty",
			questions: nil,
			want:      "No questions",
		},
		{
			name: "single short question",
			questions: []protocol.ClaudeQuestion{
				{Question: "What color?"},
			},
			want: "What color?",
		},
		{
			name: "single long question truncated",
			questions: []protocol.ClaudeQuestion{
				{Question: strings.Repeat("a", 150)},
			},
			want: strings.Repeat("a", 100) + "...",
		},
		{
			name: "multiple questions",
			questions: []protocol.ClaudeQuestion{
				{Question: "Q1"},
				{Question: "Q2"},
				{Question: "Q3"},
			},
			want: "3 questions from Claude",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatQuestionSummary(tt.questions)
			if got != tt.want {
				t.Errorf("formatQuestionSummary() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResponseHelpers_GetDecision(t *testing.T) {
	resp := &ApprovalResponse{Decision: protocol.Allow}
	if got := getDecision(resp); got != "allow" {
		t.Errorf("getDecision() = %q, want allow", got)
	}

	resp2 := &ApprovalResponse{Decision: protocol.Deny}
	if got := getDecision(resp2); got != "deny" {
		t.Errorf("getDecision() = %q, want deny", got)
	}

	resp3 := &ApprovalResponse{Decision: protocol.AllowAlways}
	if got := getDecision(resp3); got != "allow_always" {
		t.Errorf("getDecision() = %q, want allow_always", got)
	}
}

func TestResponseHelpers_GetUpdatedInput(t *testing.T) {
	// nil case
	resp := &ApprovalResponse{}
	if got := getUpdatedInput(resp); got != nil {
		t.Errorf("getUpdatedInput(nil) = %v, want nil", got)
	}

	// with value
	input := map[string]any{"command": "ls -la"}
	resp2 := &ApprovalResponse{UpdatedInput: &input}
	got := getUpdatedInput(resp2)
	if got == nil || got["command"] != "ls -la" {
		t.Errorf("getUpdatedInput() = %v, want {command: ls -la}", got)
	}
}

func TestResponseHelpers_GetErrorCode(t *testing.T) {
	// nil
	resp := &ApprovalResponse{}
	if got := getErrorCode(resp); got != nil {
		t.Errorf("getErrorCode(nil) = %v, want nil", got)
	}

	// with value
	code := protocol.AckAgentCommonSigningErrorCode(5)
	resp2 := &ApprovalResponse{}
	resp2.ErrorCode = &code
	got := getErrorCode(resp2)
	if got == nil || *got != 5 {
		t.Errorf("getErrorCode() = %v, want 5", got)
	}
}

func TestResponseHelpers_GetErrorMessage(t *testing.T) {
	resp := &ApprovalResponse{}
	if got := getErrorMessage(resp); got != "" {
		t.Errorf("getErrorMessage(nil) = %q, want empty", got)
	}

	msg := "some error"
	resp2 := &ApprovalResponse{}
	resp2.ErrorMessage = &msg
	if got := getErrorMessage(resp2); got != "some error" {
		t.Errorf("getErrorMessage() = %q, want 'some error'", got)
	}
}

func TestResponseHelpers_GetRulePattern(t *testing.T) {
	// nil
	rule := &RememberRule{}
	if got := getRulePattern(rule); got != "" {
		t.Errorf("getRulePattern(nil) = %q, want empty", got)
	}

	// with value
	pattern := "ls *"
	rule2 := &RememberRule{Pattern: &pattern}
	if got := getRulePattern(rule2); got != "ls *" {
		t.Errorf("getRulePattern() = %q, want 'ls *'", got)
	}
}

func TestResponseHelpers_GetAnswersBytes(t *testing.T) {
	resp := &QuestionResponse{}
	if got := getAnswersBytes(resp); got != nil {
		t.Errorf("getAnswersBytes(nil) = %v, want nil", got)
	}

	answersBytes := []byte(`{"q1":"a1"}`)
	resp2 := &QuestionResponse{AnswersBytes: &answersBytes}
	got := getAnswersBytes(resp2)
	if string(got) != `{"q1":"a1"}` {
		t.Errorf("getAnswersBytes() = %q", got)
	}
}

func TestResponseHelpers_GetAnswersSignature(t *testing.T) {
	resp := &QuestionResponse{}
	if got := getAnswersSignature(resp); got != nil {
		t.Errorf("getAnswersSignature(nil) = %v, want nil", got)
	}

	sig := []byte("signature-bytes")
	resp2 := &QuestionResponse{AnswersSignature: &sig}
	got := getAnswersSignature(resp2)
	if string(got) != "signature-bytes" {
		t.Errorf("getAnswersSignature() = %q", got)
	}
}

func TestResponseHelpers_GetQuestionErrorCode(t *testing.T) {
	resp := &QuestionResponse{}
	if got := getQuestionErrorCode(resp); got != nil {
		t.Errorf("getQuestionErrorCode(nil) = %v, want nil", got)
	}

	code := protocol.AckAgentCommonSigningErrorCode(1)
	resp2 := &QuestionResponse{}
	resp2.ErrorCode = &code
	got := getQuestionErrorCode(resp2)
	if got == nil || *got != 1 {
		t.Errorf("getQuestionErrorCode() = %v, want 1", got)
	}
}

func TestResponseHelpers_GetQuestionErrorMessage(t *testing.T) {
	resp := &QuestionResponse{}
	if got := getQuestionErrorMessage(resp); got != "" {
		t.Errorf("getQuestionErrorMessage(nil) = %q, want empty", got)
	}

	msg := "user declined"
	resp2 := &QuestionResponse{}
	resp2.ErrorMessage = &msg
	if got := getQuestionErrorMessage(resp2); got != "user declined" {
		t.Errorf("getQuestionErrorMessage() = %q, want 'user declined'", got)
	}
}
