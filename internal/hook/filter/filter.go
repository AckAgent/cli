// Package filter provides tool filtering and "always allow" rule matching.
package filter

import (
	"regexp"

	"github.com/ackagent/cli/internal/shared/config"
)

// DefaultFilteredTools are the tools that require approval by default.
// These are tools that can modify files or execute commands.
var DefaultFilteredTools = []string{
	"Bash",
	"Write",
	"Edit",
	"MultiEdit",
}

// ShouldFilter returns true if the tool should require approval.
func ShouldFilter(toolName string, filteredTools []string) bool {
	if filteredTools == nil {
		filteredTools = DefaultFilteredTools
	}
	for _, t := range filteredTools {
		if t == toolName {
			return true
		}
	}
	return false
}

// MatchesAlwaysAllowRule returns true if the tool/input matches an always-allow rule.
func MatchesAlwaysAllowRule(toolName string, toolInput map[string]any, rules []config.AlwaysAllowRule) bool {
	for _, rule := range rules {
		if matchesRule(toolName, toolInput, rule) {
			return true
		}
	}
	return false
}

// matchesRule checks if a single rule matches the tool/input.
func matchesRule(toolName string, toolInput map[string]any, rule config.AlwaysAllowRule) bool {
	// Tool name must match
	if rule.Tool != toolName {
		return false
	}

	// If no pattern, match all inputs for this tool
	if rule.Pattern == "" {
		return true
	}

	// Pattern matching based on tool type
	inputStr := getInputString(toolName, toolInput)
	if inputStr == "" {
		return false
	}

	// Try to match the pattern as a regex
	re, err := regexp.Compile(rule.Pattern)
	if err != nil {
		// Invalid regex, try exact match
		return inputStr == rule.Pattern
	}
	return re.MatchString(inputStr)
}

// getInputString extracts the primary input string for pattern matching.
func getInputString(toolName string, toolInput map[string]any) string {
	if toolInput == nil {
		return ""
	}

	switch toolName {
	case "Bash":
		if cmd, ok := toolInput["command"].(string); ok {
			return cmd
		}
	case "Write", "Edit", "MultiEdit":
		if path, ok := toolInput["file_path"].(string); ok {
			return path
		}
	}
	return ""
}

// CreateRulePattern creates a pattern for an always-allow rule.
// For Bash commands, it creates a pattern that matches similar commands.
// For file operations, it creates a pattern for the file path.
func CreateRulePattern(toolName string, toolInput map[string]any) string {
	inputStr := getInputString(toolName, toolInput)
	if inputStr == "" {
		return ""
	}

	switch toolName {
	case "Bash":
		// For Bash, use the command as-is (exact match)
		// This is conservative - users can manually create more permissive patterns
		return regexp.QuoteMeta(inputStr)
	case "Write", "Edit", "MultiEdit":
		// For file operations, use the exact file path
		return regexp.QuoteMeta(inputStr)
	default:
		return regexp.QuoteMeta(inputStr)
	}
}
