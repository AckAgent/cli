package claude

import (
	"strings"
	"testing"
)

func TestHookInput_IsPreToolUse(t *testing.T) {
	tests := []struct {
		event string
		want  bool
	}{
		{"PreToolUse", true},
		{"PermissionRequest", false},
		{"PostToolUse", false},
		{"Stop", false},
		{"", false},
	}
	for _, tt := range tests {
		h := &HookInput{HookEventName: tt.event}
		if got := h.IsPreToolUse(); got != tt.want {
			t.Errorf("IsPreToolUse(%q) = %v, want %v", tt.event, got, tt.want)
		}
	}
}

func TestHookInput_IsAskUserQuestion(t *testing.T) {
	tests := []struct {
		tool string
		want bool
	}{
		{"AskUserQuestion", true},
		{"Bash", false},
		{"", false},
	}
	for _, tt := range tests {
		h := &HookInput{ToolName: tt.tool}
		if got := h.IsAskUserQuestion(); got != tt.want {
			t.Errorf("IsAskUserQuestion(%q) = %v, want %v", tt.tool, got, tt.want)
		}
	}
}

func TestHookInput_GetQuestions_Valid(t *testing.T) {
	h := &HookInput{
		ToolInput: map[string]any{
			"questions": []any{
				map[string]any{
					"question": "What color?",
					"options": []any{
						map[string]any{"label": "Red", "description": "Warm"},
						map[string]any{"label": "Blue", "description": "Cool"},
					},
					"multiSelect": false,
				},
			},
		},
	}

	questions, err := h.GetQuestions()
	if err != nil {
		t.Fatalf("GetQuestions() error = %v", err)
	}
	if len(questions) != 1 {
		t.Fatalf("len(questions) = %d, want 1", len(questions))
	}
	if questions[0].Question != "What color?" {
		t.Errorf("question = %q, want 'What color?'", questions[0].Question)
	}
}

func TestHookInput_GetQuestions_NilInput(t *testing.T) {
	h := &HookInput{ToolInput: nil}
	_, err := h.GetQuestions()
	if err == nil {
		t.Error("expected error for nil ToolInput")
	}
}

func TestHookInput_GetQuestions_NoQuestionsField(t *testing.T) {
	h := &HookInput{ToolInput: map[string]any{"other": "value"}}
	_, err := h.GetQuestions()
	if err == nil {
		t.Error("expected error for missing questions field")
	}
}

func TestHookInput_GetQuestions_InvalidStructure(t *testing.T) {
	h := &HookInput{
		ToolInput: map[string]any{
			"questions": "not-an-array",
		},
	}
	_, err := h.GetQuestions()
	if err == nil {
		t.Error("expected error for invalid questions structure")
	}
}

func TestHookInput_FormatToolInput_NilInput(t *testing.T) {
	h := &HookInput{ToolName: "Bash", ToolInput: nil}
	got := h.FormatToolInput()
	if got != "null" {
		t.Errorf("FormatToolInput() with nil input = %q, want null", got)
	}
}

func TestHookInput_FormatToolInput_LongJSON(t *testing.T) {
	// For unknown tool with very long JSON input
	h := &HookInput{
		ToolName:  "CustomTool",
		ToolInput: map[string]any{"key": strings.Repeat("x", 300)},
	}
	got := h.FormatToolInput()
	if len(got) > 204 { // 200 + "..."
		t.Errorf("FormatToolInput() length = %d, should be truncated", len(got))
	}
}

func TestHookInput_FormatToolInput_Edit(t *testing.T) {
	h := &HookInput{
		ToolName:  "Edit",
		ToolInput: map[string]any{"file_path": "/path/to/file.go"},
	}
	if got := h.FormatToolInput(); got != "/path/to/file.go" {
		t.Errorf("FormatToolInput() = %q, want /path/to/file.go", got)
	}
}

func TestHookInput_FormatToolInput_MultiEdit(t *testing.T) {
	h := &HookInput{
		ToolName:  "MultiEdit",
		ToolInput: map[string]any{"file_path": "/path/to/file.go"},
	}
	if got := h.FormatToolInput(); got != "/path/to/file.go" {
		t.Errorf("FormatToolInput() = %q, want /path/to/file.go", got)
	}
}

func TestReadInput_PreToolUseEvent(t *testing.T) {
	input := `{
		"session_id": "sess-1",
		"hook_event_name": "PreToolUse",
		"tool_name": "AskUserQuestion",
		"tool_input": {
			"questions": [
				{"question": "Q1?", "options": [{"label": "A", "description": "option A"}], "multiSelect": false}
			]
		}
	}`
	reader := strings.NewReader(input)
	h, err := ReadInput(reader)
	if err != nil {
		t.Fatalf("ReadInput() error = %v", err)
	}
	if !h.IsPreToolUse() {
		t.Error("expected IsPreToolUse() = true")
	}
	if !h.IsAskUserQuestion() {
		t.Error("expected IsAskUserQuestion() = true")
	}
}
