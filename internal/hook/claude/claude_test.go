package claude

import (
	"testing"
	"time"

	"github.com/ackagent/cli/internal/hook/filter"
	"github.com/ackagent/cli/internal/shared/config"
)

func TestGetHookSettings_NilSettings(t *testing.T) {
	cfg := &config.Config{
		Version:       config.ConfigVersion,
		ActiveProfile: config.DefaultProfileName,
		Profiles: map[string]*config.ProfileConfig{
			config.DefaultProfileName: {
				RelayURL:     "http://localhost:8080",
				HookSettings: nil, // No settings
			},
		},
	}

	settings := getHookSettings(cfg)

	if settings == nil {
		t.Fatal("getHookSettings returned nil")
	}

	// Should return defaults
	if len(settings.FilteredTools) == 0 {
		t.Error("Expected default filtered tools")
	}
	if settings.TimeoutSeconds != int(DefaultTimeout.Seconds()) {
		t.Errorf("Expected default timeout %v, got %v", DefaultTimeout.Seconds(), settings.TimeoutSeconds)
	}
}

func TestGetHookSettings_CustomSettings(t *testing.T) {
	customSettings := &config.HookSettings{
		FilteredTools:    []string{"CustomTool"},
		AlwaysAllowRules: []config.AlwaysAllowRule{{ID: "rule-1", Tool: "Bash"}},
		TimeoutSeconds:   300,
	}

	cfg := &config.Config{
		Version:       config.ConfigVersion,
		ActiveProfile: config.DefaultProfileName,
		Profiles: map[string]*config.ProfileConfig{
			config.DefaultProfileName: {
				RelayURL:     "http://localhost:8080",
				HookSettings: customSettings,
			},
		},
	}

	settings := getHookSettings(cfg)

	if settings != customSettings {
		t.Error("Expected custom settings to be returned")
	}
	if len(settings.FilteredTools) != 1 || settings.FilteredTools[0] != "CustomTool" {
		t.Error("Custom filtered tools not preserved")
	}
	if len(settings.AlwaysAllowRules) != 1 {
		t.Error("Custom rules not preserved")
	}
	if settings.TimeoutSeconds != 300 {
		t.Errorf("Custom timeout not preserved: got %v", settings.TimeoutSeconds)
	}
}

func TestGetTimeout_DefaultTimeout(t *testing.T) {
	settings := &config.HookSettings{
		TimeoutSeconds: 0, // Use default
	}

	timeout := getTimeout(settings)

	if timeout != DefaultTimeout {
		t.Errorf("Expected default timeout %v, got %v", DefaultTimeout, timeout)
	}
}

func TestGetTimeout_CustomTimeout(t *testing.T) {
	settings := &config.HookSettings{
		TimeoutSeconds: 300, // 5 minutes
	}

	timeout := getTimeout(settings)

	expected := 300 * time.Second
	if timeout != expected {
		t.Errorf("Expected timeout %v, got %v", expected, timeout)
	}
}

func TestGetTimeout_NegativeTimeout(t *testing.T) {
	settings := &config.HookSettings{
		TimeoutSeconds: -1, // Invalid, should use default
	}

	timeout := getTimeout(settings)

	if timeout != DefaultTimeout {
		t.Errorf("Expected default timeout for negative value, got %v", timeout)
	}
}

func TestApprovalResult_ToHookOutput_Approved(t *testing.T) {
	result := &ApprovalResult{
		Approved:    true,
		AlwaysAllow: false,
		Message:     "Request approved",
	}

	output := result.ToHookOutput()

	// For approved, top-level Decision should be nil (no block)
	if output.Decision != nil {
		t.Errorf("Expected nil Decision for approved, got %v", *output.Decision)
	}

	// Check HookSpecificOutput
	if output.HookSpecificOutput == nil {
		t.Fatal("Expected HookSpecificOutput to be set")
	}
	if output.HookSpecificOutput.Decision == nil {
		t.Fatal("Expected HookSpecificOutput.Decision to be set")
	}
	if output.HookSpecificOutput.Decision.Behavior != "allow" {
		t.Errorf("Expected Behavior 'allow', got %q", output.HookSpecificOutput.Decision.Behavior)
	}
	if output.HookSpecificOutput.Decision.Message != "Request approved" {
		t.Errorf("Expected Message 'Request approved', got %q", output.HookSpecificOutput.Decision.Message)
	}
}

func TestApprovalResult_ToHookOutput_Denied(t *testing.T) {
	result := &ApprovalResult{
		Approved: false,
		Message:  "Request denied",
	}

	output := result.ToHookOutput()

	// For denied, top-level Decision should be "block"
	if output.Decision == nil {
		t.Fatal("Expected Decision to be set for denied")
	}
	if *output.Decision != "block" {
		t.Errorf("Expected Decision 'block', got %q", *output.Decision)
	}
	if output.Reason != "Request denied" {
		t.Errorf("Expected Reason 'Request denied', got %q", output.Reason)
	}

	// Check HookSpecificOutput
	if output.HookSpecificOutput == nil {
		t.Fatal("Expected HookSpecificOutput to be set")
	}
	if output.HookSpecificOutput.Decision == nil {
		t.Fatal("Expected HookSpecificOutput.Decision to be set")
	}
	if output.HookSpecificOutput.Decision.Behavior != "deny" {
		t.Errorf("Expected Behavior 'deny', got %q", output.HookSpecificOutput.Decision.Behavior)
	}
}

func TestApprovalResult_ToHookOutput_WithUpdatedInput(t *testing.T) {
	result := &ApprovalResult{
		Approved:     true,
		UpdatedInput: map[string]any{"command": "ls -la"},
	}

	output := result.ToHookOutput()

	if output.HookSpecificOutput == nil || output.HookSpecificOutput.Decision == nil {
		t.Fatal("Expected HookSpecificOutput.Decision to be set")
	}

	if output.HookSpecificOutput.Decision.Behavior != "allow" {
		t.Errorf("Expected Behavior 'allow', got %q", output.HookSpecificOutput.Decision.Behavior)
	}

	if output.HookSpecificOutput.Decision.UpdatedInput == nil {
		t.Fatal("Expected UpdatedInput to be set")
	}
	if output.HookSpecificOutput.Decision.UpdatedInput["command"] != "ls -la" {
		t.Errorf("Unexpected UpdatedInput: %v", output.HookSpecificOutput.Decision.UpdatedInput)
	}
}

func TestQuestionResult_ToHookOutput_Answered(t *testing.T) {
	result := &QuestionResult{
		Answered: true,
		Answers:  map[string]string{"q1": "answer1", "q2": "answer2"},
		Message:  "Questions answered",
	}

	output := result.ToHookOutput()

	if output.HookSpecificOutput == nil {
		t.Fatal("Expected HookSpecificOutput to be set")
	}

	if output.HookSpecificOutput.HookEventName != "PreToolUse" {
		t.Errorf("Expected HookEventName 'PreToolUse', got %q", output.HookSpecificOutput.HookEventName)
	}

	if output.HookSpecificOutput.PermissionDecision != "allow" {
		t.Errorf("Expected PermissionDecision 'allow', got %q", output.HookSpecificOutput.PermissionDecision)
	}

	if output.HookSpecificOutput.UpdatedInput == nil {
		t.Fatal("Expected UpdatedInput to be set")
	}

	answersRaw, ok := output.HookSpecificOutput.UpdatedInput["answers"]
	if !ok {
		t.Fatal("Expected answers in UpdatedInput")
	}

	answers, ok := answersRaw.(map[string]any)
	if !ok {
		t.Fatalf("Expected answers to be map[string]any, got %T", answersRaw)
	}

	if answers["q1"] != "answer1" {
		t.Errorf("Answer q1 mismatch: got %v", answers["q1"])
	}
	if answers["q2"] != "answer2" {
		t.Errorf("Answer q2 mismatch: got %v", answers["q2"])
	}
}

func TestQuestionResult_ToHookOutput_NotAnswered(t *testing.T) {
	result := &QuestionResult{
		Answered: false,
	}

	output := result.ToHookOutput()

	// Not answered should passthrough (empty output)
	if output.Decision != nil {
		t.Errorf("Expected nil Decision for unanswered, got %v", *output.Decision)
	}
	if output.HookSpecificOutput != nil {
		t.Errorf("Expected nil HookSpecificOutput for unanswered")
	}
}

func TestDefaultFilteredTools(t *testing.T) {
	// Verify the default filtered tools are set correctly
	expected := []string{"Bash", "Write", "Edit", "MultiEdit"}

	if len(filter.DefaultFilteredTools) != len(expected) {
		t.Errorf("Expected %d default filtered tools, got %d", len(expected), len(filter.DefaultFilteredTools))
	}

	for i, tool := range expected {
		if filter.DefaultFilteredTools[i] != tool {
			t.Errorf("Default tool %d mismatch: expected %q, got %q", i, tool, filter.DefaultFilteredTools[i])
		}
	}
}

func TestDefaultTimeout(t *testing.T) {
	// Default timeout should be reasonable (e.g., 120 seconds)
	if DefaultTimeout < 30*time.Second {
		t.Errorf("Default timeout too short: %v", DefaultTimeout)
	}
	if DefaultTimeout > 10*time.Minute {
		t.Errorf("Default timeout too long: %v", DefaultTimeout)
	}
}

// Note: TestAllowOutput, TestDenyOutput, TestPassthroughOutput, TestAllowWithUpdatedInput
// are already defined in output_test.go
