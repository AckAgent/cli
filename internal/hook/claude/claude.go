package claude

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/ackagent/cli/internal/hook/approval"
	"github.com/ackagent/cli/internal/hook/filter"
	"github.com/ackagent/cli/internal/shared/config"
	"github.com/ackagent/cli/internal/shared/log"
)

var hookLog = log.New("hook")

// DefaultTimeout is the default timeout for waiting for iOS approval.
var DefaultTimeout = config.DefaultSigningTimeout

// Run handles the Claude Code hook.
// It reads input from stdin, processes the approval request, and writes output to stdout.
func Run() error {
	// Read input from stdin
	input, err := ReadInput(os.Stdin)
	if err != nil {
		hookLog.Error("failed to read input: %v", err)
		return fmt.Errorf("reading input: %w", err)
	}

	hookLog.Debug("received event=%s tool=%s", input.HookEventName, input.ToolName)

	// Validate input
	if err := input.Validate(); err != nil {
		hookLog.Error("invalid input: %v", err)
		return fmt.Errorf("invalid input: %w", err)
	}

	// Handle PreToolUse events for AskUserQuestion
	if input.IsPreToolUse() && input.IsAskUserQuestion() {
		hookLog.Debug("handling AskUserQuestion")
		return handleAskUserQuestion(input)
	}

	// Only handle PermissionRequest events for other tools
	if !input.IsPermissionRequest() {
		// Pass through for unsupported events
		hookLog.Debug("passthrough: not a PermissionRequest")
		return WriteOutput(os.Stdout, PassthroughOutput())
	}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		// If config doesn't exist, pass through (not paired)
		hookLog.Debug("passthrough: config not found")
		return WriteOutput(os.Stdout, PassthroughOutput())
	}

	// Check if logged in
	if !cfg.IsLoggedIn() {
		// Not logged in, pass through to default behavior
		hookLog.Debug("passthrough: not logged in")
		return WriteOutput(os.Stdout, PassthroughOutput())
	}

	// Get hook settings
	hookSettings := getHookSettings(cfg)

	// Check tool filter
	if !filter.ShouldFilter(input.ToolName, hookSettings.FilteredTools) {
		// Tool not filtered, allow immediately
		hookLog.Debug("allow: tool %s not in filter list", input.ToolName)
		return WriteOutput(os.Stdout, AllowOutput("Tool not filtered"))
	}

	// Check "always allow" rules
	if filter.MatchesAlwaysAllowRule(input.ToolName, input.ToolInput, hookSettings.AlwaysAllowRules) {
		hookLog.Debug("allow: matched always-allow rule for %s", input.ToolName)
		return WriteOutput(os.Stdout, AllowOutput("Matched always-allow rule"))
	}

	// Send approval request to iOS
	hookLog.Debug("requesting approval for %s", input.ToolName)
	ctx, cancel := context.WithTimeout(context.Background(), getTimeout(hookSettings))
	defer cancel()

	result, err := approval.RequestApproval(ctx, cfg, &approval.ApprovalContext{
		SessionID: input.SessionID,
		ToolName:  input.ToolName,
		ToolInput: input.ToolInput,
		Timestamp: time.Now().UnixMilli(),
	})

	if err != nil {
		// On error (including timeout), deny by default
		hookLog.Error("approval failed: %v", err)
		return WriteOutput(os.Stdout, DenyOutput(fmt.Sprintf("Approval failed: %v", err)))
	}

	if result.Approved {
		hookLog.Debug("approved tool=%s always_allow=%v", input.ToolName, result.AlwaysAllow)
	} else {
		hookLog.Debug("denied tool=%s", input.ToolName)
	}

	// If "always allow" was selected, save the rule
	if result.AlwaysAllow && result.Approved {
		rule := config.AlwaysAllowRule{
			ID:        result.RuleID,
			Tool:      input.ToolName,
			Pattern:   result.RulePattern,
			CreatedAt: time.Now(),
		}
		if err := saveAlwaysAllowRule(cfg, rule); err != nil {
			// Log but don't fail
			hookLog.Warn("failed to save always-allow rule: %v", err)
		}
	}

	// Convert result to hook output
	hookResult := &ApprovalResult{
		Approved:     result.Approved,
		AlwaysAllow:  result.AlwaysAllow,
		UpdatedInput: result.UpdatedInput,
		Message:      result.Message,
	}

	return WriteOutput(os.Stdout, hookResult.ToHookOutput())
}

// getHookSettings returns the hook settings from config, with defaults.
func getHookSettings(cfg *config.Config) *config.HookSettings {
	settings := cfg.HookSettings()
	if settings != nil {
		return settings
	}
	// Return defaults
	return &config.HookSettings{
		FilteredTools:    filter.DefaultFilteredTools,
		AlwaysAllowRules: nil,
		TimeoutSeconds:   int(DefaultTimeout.Seconds()),
	}
}

// getTimeout returns the timeout duration from settings.
func getTimeout(settings *config.HookSettings) time.Duration {
	if settings.TimeoutSeconds > 0 {
		return time.Duration(settings.TimeoutSeconds) * time.Second
	}
	return DefaultTimeout
}

// saveAlwaysAllowRule saves an always-allow rule to the config.
func saveAlwaysAllowRule(cfg *config.Config, rule config.AlwaysAllowRule) error {
	settings := cfg.HookSettings()
	if settings == nil {
		settings = &config.HookSettings{
			FilteredTools: filter.DefaultFilteredTools,
		}
	}
	settings.AlwaysAllowRules = append(settings.AlwaysAllowRules, config.AlwaysAllowRule{
		ID:        rule.ID,
		Tool:      rule.Tool,
		Pattern:   rule.Pattern,
		CreatedAt: rule.CreatedAt,
	})
	cfg.SetHookSettings(settings)
	return cfg.Save()
}

// handleAskUserQuestion handles PreToolUse events for AskUserQuestion tool.
// It sends questions to iOS for remote answering and returns the answers to Claude.
func handleAskUserQuestion(input *HookInput) error {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		// If config doesn't exist, pass through (not paired)
		return WriteOutput(os.Stdout, PassthroughOutput())
	}

	// Check if logged in
	if !cfg.IsLoggedIn() {
		// Not logged in, pass through to default behavior
		return WriteOutput(os.Stdout, PassthroughOutput())
	}

	// Extract questions from input (already uses generated protocol types)
	questions, err := input.GetQuestions()
	if err != nil {
		// Can't parse questions, pass through
		fmt.Fprintf(os.Stderr, "warning: failed to parse questions: %v\n", err)
		return WriteOutput(os.Stdout, PassthroughOutput())
	}

	if len(questions) == 0 {
		// No questions, pass through
		return WriteOutput(os.Stdout, PassthroughOutput())
	}

	// Get hook settings for timeout
	hookSettings := getHookSettings(cfg)

	// Send question request to iOS (questions are already protocol.ClaudeQuestion)
	ctx, cancel := context.WithTimeout(context.Background(), getTimeout(hookSettings))
	defer cancel()

	result, err := approval.RequestQuestionAnswers(ctx, cfg, &approval.QuestionContext{
		SessionID: input.SessionID,
		Questions: questions,
		Timestamp: time.Now().UnixMilli(),
	})

	if err != nil {
		// On error (including timeout), pass through to local prompting
		fmt.Fprintf(os.Stderr, "warning: question request failed: %v\n", err)
		return WriteOutput(os.Stdout, PassthroughOutput())
	}

	// If not answered (user declined), pass through to local prompting
	if !result.Answered {
		return WriteOutput(os.Stdout, PassthroughOutput())
	}

	// Return answers to Claude
	questionResult := &QuestionResult{
		Answered: true,
		Answers:  result.Answers,
		Message:  result.Message,
	}

	return WriteOutput(os.Stdout, questionResult.ToHookOutput())
}
