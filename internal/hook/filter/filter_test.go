package filter

import (
	"testing"
	"time"

	"github.com/ackagent/cli/internal/shared/config"
)

func TestDefaultFilteredTools(t *testing.T) {
	expected := []string{"Bash", "Write", "Edit", "MultiEdit"}
	if len(DefaultFilteredTools) != len(expected) {
		t.Errorf("DefaultFilteredTools length = %d, want %d", len(DefaultFilteredTools), len(expected))
	}
	for i, tool := range expected {
		if DefaultFilteredTools[i] != tool {
			t.Errorf("DefaultFilteredTools[%d] = %v, want %v", i, DefaultFilteredTools[i], tool)
		}
	}
}

func TestShouldFilter(t *testing.T) {
	tests := []struct {
		name          string
		toolName      string
		filteredTools []string
		want          bool
	}{
		{
			name:          "bash with default filters",
			toolName:      "Bash",
			filteredTools: nil,
			want:          true,
		},
		{
			name:          "write with default filters",
			toolName:      "Write",
			filteredTools: nil,
			want:          true,
		},
		{
			name:          "edit with default filters",
			toolName:      "Edit",
			filteredTools: nil,
			want:          true,
		},
		{
			name:          "multiedit with default filters",
			toolName:      "MultiEdit",
			filteredTools: nil,
			want:          true,
		},
		{
			name:          "read tool not filtered by default",
			toolName:      "Read",
			filteredTools: nil,
			want:          false,
		},
		{
			name:          "glob tool not filtered by default",
			toolName:      "Glob",
			filteredTools: nil,
			want:          false,
		},
		{
			name:          "custom filter list includes tool",
			toolName:      "CustomTool",
			filteredTools: []string{"CustomTool", "AnotherTool"},
			want:          true,
		},
		{
			name:          "custom filter list excludes tool",
			toolName:      "SafeTool",
			filteredTools: []string{"CustomTool", "AnotherTool"},
			want:          false,
		},
		{
			name:          "empty filter list",
			toolName:      "Bash",
			filteredTools: []string{},
			want:          false,
		},
		{
			name:          "case sensitive matching",
			toolName:      "bash",
			filteredTools: nil,
			want:          false, // "bash" != "Bash"
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ShouldFilter(tt.toolName, tt.filteredTools)
			if got != tt.want {
				t.Errorf("ShouldFilter(%q, %v) = %v, want %v", tt.toolName, tt.filteredTools, got, tt.want)
			}
		})
	}
}

func TestMatchesAlwaysAllowRule(t *testing.T) {
	tests := []struct {
		name      string
		toolName  string
		toolInput map[string]any
		rules     []config.AlwaysAllowRule
		want      bool
	}{
		{
			name:      "no rules",
			toolName:  "Bash",
			toolInput: map[string]any{"command": "ls"},
			rules:     nil,
			want:      false,
		},
		{
			name:      "empty rules",
			toolName:  "Bash",
			toolInput: map[string]any{"command": "ls"},
			rules:     []config.AlwaysAllowRule{},
			want:      false,
		},
		{
			name:      "tool match without pattern",
			toolName:  "Bash",
			toolInput: map[string]any{"command": "ls"},
			rules: []config.AlwaysAllowRule{
				{ID: "1", Tool: "Bash", Pattern: "", CreatedAt: time.Now()},
			},
			want: true,
		},
		{
			name:      "tool mismatch",
			toolName:  "Write",
			toolInput: map[string]any{"file_path": "/tmp/test.txt"},
			rules: []config.AlwaysAllowRule{
				{ID: "1", Tool: "Bash", Pattern: "", CreatedAt: time.Now()},
			},
			want: false,
		},
		{
			name:      "exact pattern match for bash command",
			toolName:  "Bash",
			toolInput: map[string]any{"command": "ls -la"},
			rules: []config.AlwaysAllowRule{
				{ID: "1", Tool: "Bash", Pattern: "ls -la", CreatedAt: time.Now()},
			},
			want: true,
		},
		{
			name:      "regex pattern match",
			toolName:  "Bash",
			toolInput: map[string]any{"command": "npm run build"},
			rules: []config.AlwaysAllowRule{
				{ID: "1", Tool: "Bash", Pattern: "npm run .*", CreatedAt: time.Now()},
			},
			want: true,
		},
		{
			name:      "regex pattern no match",
			toolName:  "Bash",
			toolInput: map[string]any{"command": "rm -rf /"},
			rules: []config.AlwaysAllowRule{
				{ID: "1", Tool: "Bash", Pattern: "npm run .*", CreatedAt: time.Now()},
			},
			want: false,
		},
		{
			name:      "file path pattern match",
			toolName:  "Write",
			toolInput: map[string]any{"file_path": "/tmp/test.txt"},
			rules: []config.AlwaysAllowRule{
				{ID: "1", Tool: "Write", Pattern: "/tmp/.*\\.txt", CreatedAt: time.Now()},
			},
			want: true,
		},
		{
			name:      "file path pattern no match",
			toolName:  "Write",
			toolInput: map[string]any{"file_path": "/etc/passwd"},
			rules: []config.AlwaysAllowRule{
				{ID: "1", Tool: "Write", Pattern: "/tmp/.*", CreatedAt: time.Now()},
			},
			want: false,
		},
		{
			name:      "multiple rules - first matches",
			toolName:  "Bash",
			toolInput: map[string]any{"command": "git status"},
			rules: []config.AlwaysAllowRule{
				{ID: "1", Tool: "Bash", Pattern: "git .*", CreatedAt: time.Now()},
				{ID: "2", Tool: "Bash", Pattern: "npm .*", CreatedAt: time.Now()},
			},
			want: true,
		},
		{
			name:      "multiple rules - second matches",
			toolName:  "Bash",
			toolInput: map[string]any{"command": "npm install"},
			rules: []config.AlwaysAllowRule{
				{ID: "1", Tool: "Bash", Pattern: "git .*", CreatedAt: time.Now()},
				{ID: "2", Tool: "Bash", Pattern: "npm .*", CreatedAt: time.Now()},
			},
			want: true,
		},
		{
			name:      "nil tool input",
			toolName:  "Bash",
			toolInput: nil,
			rules: []config.AlwaysAllowRule{
				{ID: "1", Tool: "Bash", Pattern: "ls", CreatedAt: time.Now()},
			},
			want: false,
		},
		{
			name:      "nil tool input with no pattern",
			toolName:  "Bash",
			toolInput: nil,
			rules: []config.AlwaysAllowRule{
				{ID: "1", Tool: "Bash", Pattern: "", CreatedAt: time.Now()},
			},
			want: true, // No pattern means match all for this tool
		},
		{
			name:      "invalid regex falls back to exact match - no match",
			toolName:  "Bash",
			toolInput: map[string]any{"command": "ls"},
			rules: []config.AlwaysAllowRule{
				{ID: "1", Tool: "Bash", Pattern: "[invalid(regex", CreatedAt: time.Now()},
			},
			want: false,
		},
		{
			name:      "invalid regex falls back to exact match - matches",
			toolName:  "Bash",
			toolInput: map[string]any{"command": "[invalid(regex"},
			rules: []config.AlwaysAllowRule{
				{ID: "1", Tool: "Bash", Pattern: "[invalid(regex", CreatedAt: time.Now()},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchesAlwaysAllowRule(tt.toolName, tt.toolInput, tt.rules)
			if got != tt.want {
				t.Errorf("MatchesAlwaysAllowRule(%q, %v, rules) = %v, want %v", tt.toolName, tt.toolInput, got, tt.want)
			}
		})
	}
}

func TestCreateRulePattern(t *testing.T) {
	tests := []struct {
		name      string
		toolName  string
		toolInput map[string]any
		want      string
	}{
		{
			name:      "bash command",
			toolName:  "Bash",
			toolInput: map[string]any{"command": "ls -la"},
			want:      "ls -la", // regexp.QuoteMeta escapes nothing here
		},
		{
			name:      "bash command with special chars",
			toolName:  "Bash",
			toolInput: map[string]any{"command": "rm -rf /tmp/*.txt"},
			want:      `rm -rf /tmp/\*\.txt`, // Escaped
		},
		{
			name:      "write file path",
			toolName:  "Write",
			toolInput: map[string]any{"file_path": "/tmp/test.txt"},
			want:      `/tmp/test\.txt`,
		},
		{
			name:      "nil input",
			toolName:  "Bash",
			toolInput: nil,
			want:      "",
		},
		{
			name:      "missing key",
			toolName:  "Bash",
			toolInput: map[string]any{"other": "value"},
			want:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CreateRulePattern(tt.toolName, tt.toolInput)
			if got != tt.want {
				t.Errorf("CreateRulePattern(%q, %v) = %q, want %q", tt.toolName, tt.toolInput, got, tt.want)
			}
		})
	}
}
