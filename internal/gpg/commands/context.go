package commands

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ackagent/cli/internal/gpg/cli"
)

const (
	// ContentPreviewLimit is the max chars for content preview
	ContentPreviewLimit = 500
	// ContentInlineLimit is the max bytes to include full content
	ContentInlineLimit = 2048
)

// GitCommitContext contains parsed git commit object data
type GitCommitContext struct {
	TreeHash       string   `json:"treeHash"`
	ParentHashes   []string `json:"parentHashes"`
	AuthorName     string   `json:"authorName"`
	AuthorEmail    string   `json:"authorEmail"`
	AuthorTime     int64    `json:"authorTimestamp"`
	CommitterName  string   `json:"committerName"`
	CommitterEmail string   `json:"committerEmail"`
	CommitterTime  int64    `json:"committerTimestamp"`
	Message        string   `json:"message"`
	Branch         string   `json:"branch,omitempty"`
	RepoName       string   `json:"repoName,omitempty"`
}

// GeneralGPGContext contains context for non-git GPG operations
type GeneralGPGContext struct {
	CommandLine    string `json:"commandLine"`
	OperationType  string `json:"operationType"`
	InputSource    string `json:"inputSource"`
	IsStdin        bool   `json:"isStdin"`
	ContentSize    int    `json:"contentSize"`
	ContentHash    string `json:"contentHash"`
	ContentPreview string `json:"contentPreview,omitempty"`
	ContentFull    string `json:"contentFull,omitempty"`
}

// GPGOperationContext wraps either git or general context
type GPGOperationContext struct {
	IsGitCommit    bool               `json:"isGitCommit"`
	GitContext     *GitCommitContext  `json:"git,omitempty"`
	GeneralContext *GeneralGPGContext `json:"general,omitempty"`
}

// ParseGitCommitObject parses a raw git commit object
func ParseGitCommitObject(data []byte) *GitCommitContext {
	content := string(data)

	// Git commit objects have a specific format: "tree <hash>\nparent <hash>\nauthor..."
	if !strings.HasPrefix(content, "tree ") {
		return nil
	}

	// Additional check for author line
	if !strings.Contains(content, "\nauthor ") {
		return nil
	}

	ctx := &GitCommitContext{
		ParentHashes: []string{},
	}

	lines := strings.Split(content, "\n")
	inMessage := false
	var messageLines []string

	for _, line := range lines {
		if inMessage {
			messageLines = append(messageLines, line)
			continue
		}

		if line == "" {
			inMessage = true
			continue
		}

		switch {
		case strings.HasPrefix(line, "tree "):
			ctx.TreeHash = strings.TrimPrefix(line, "tree ")
		case strings.HasPrefix(line, "parent "):
			ctx.ParentHashes = append(ctx.ParentHashes, strings.TrimPrefix(line, "parent "))
		case strings.HasPrefix(line, "author "):
			name, email, ts := parseGitIdentity(strings.TrimPrefix(line, "author "))
			ctx.AuthorName = name
			ctx.AuthorEmail = email
			ctx.AuthorTime = ts
		case strings.HasPrefix(line, "committer "):
			name, email, ts := parseGitIdentity(strings.TrimPrefix(line, "committer "))
			ctx.CommitterName = name
			ctx.CommitterEmail = email
			ctx.CommitterTime = ts
		}
	}

	ctx.Message = strings.Join(messageLines, "\n")
	// Trim trailing newlines from message
	ctx.Message = strings.TrimRight(ctx.Message, "\n")

	// Try to get branch and repo info
	ctx.Branch = getGitBranch()
	ctx.RepoName = getGitRepoName()

	return ctx
}

// parseGitIdentity parses "Name <email> timestamp timezone"
func parseGitIdentity(s string) (name, email string, timestamp int64) {
	// Format: "Author Name <email@example.com> 1234567890 +0000"
	emailStart := strings.LastIndex(s, "<")
	emailEnd := strings.LastIndex(s, ">")

	if emailStart > 0 && emailEnd > emailStart {
		name = strings.TrimSpace(s[:emailStart])
		email = s[emailStart+1 : emailEnd]

		// Parse timestamp from remaining
		rest := strings.TrimSpace(s[emailEnd+1:])
		parts := strings.Fields(rest)
		if len(parts) >= 1 {
			ts, err := strconv.ParseInt(parts[0], 10, 64)
			if err == nil {
				timestamp = ts
			}
		}
	}
	return
}

// getGitBranch attempts to get the current git branch
func getGitBranch() string {
	// First check environment variable (set by some git operations)
	if branch := os.Getenv("GIT_BRANCH"); branch != "" {
		return branch
	}

	// Try git symbolic-ref
	cmd := exec.Command("git", "symbolic-ref", "--short", "HEAD")
	out, err := cmd.Output()
	if err == nil {
		return strings.TrimSpace(string(out))
	}

	// Try GIT_DIR environment for detached HEAD or special cases
	if gitDir := os.Getenv("GIT_DIR"); gitDir != "" {
		headPath := filepath.Join(gitDir, "HEAD")
		if data, err := os.ReadFile(headPath); err == nil {
			content := strings.TrimSpace(string(data))
			if strings.HasPrefix(content, "ref: refs/heads/") {
				return strings.TrimPrefix(content, "ref: refs/heads/")
			}
		}
	}

	return ""
}

// getGitRepoName attempts to get the repository name
func getGitRepoName() string {
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}

	path := strings.TrimSpace(string(out))
	return filepath.Base(path)
}

// BuildGeneralContext creates context for non-git GPG operations
func BuildGeneralContext(args *cli.Args, data []byte) *GeneralGPGContext {
	ctx := &GeneralGPGContext{
		CommandLine:   reconstructCommandLine(args),
		OperationType: getOperationType(args),
		ContentSize:   len(data),
		ContentHash:   computeSHA256(data),
	}

	// Determine input source
	if args.InputFile != "" && args.InputFile != "-" {
		ctx.InputSource = args.InputFile
		ctx.IsStdin = false
	} else {
		ctx.InputSource = "stdin"
		ctx.IsStdin = true
	}

	// Add content if it's text-like
	if isLikelyText(data) {
		content := string(data)
		if len(data) <= ContentInlineLimit {
			// Small content: include full content
			ctx.ContentFull = content
		} else {
			// Large content: include preview only
			if len(content) > ContentPreviewLimit {
				ctx.ContentPreview = content[:ContentPreviewLimit] + "..."
			} else {
				ctx.ContentPreview = content
			}
		}
	}

	return ctx
}

// reconstructCommandLine builds the command line from parsed args
func reconstructCommandLine(args *cli.Args) string {
	parts := []string{"ackagent", "gpg"}

	switch args.Mode {
	case cli.ModeDetach:
		parts = append(parts, "--detach-sign")
	case cli.ModeSign:
		parts = append(parts, "--sign")
	}

	if args.Armor {
		parts = append(parts, "--armor")
	}
	if args.LocalUser != "" {
		parts = append(parts, "-u", args.LocalUser)
	}
	if args.OutputFile != "" {
		parts = append(parts, "-o", args.OutputFile)
	}
	if args.InputFile != "" && args.InputFile != "-" {
		parts = append(parts, args.InputFile)
	}

	return strings.Join(parts, " ")
}

// getOperationType returns the operation type string
func getOperationType(args *cli.Args) string {
	switch args.Mode {
	case cli.ModeDetach:
		return "detach-sign"
	case cli.ModeSign:
		return "sign"
	default:
		return "sign"
	}
}

// computeSHA256 computes the SHA256 hash of data
func computeSHA256(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// isLikelyText checks if data appears to be text (no null bytes in first 512 bytes)
func isLikelyText(data []byte) bool {
	check := data
	if len(check) > 512 {
		check = data[:512]
	}
	for _, b := range check {
		if b == 0 {
			return false
		}
	}
	return true
}

// ExtractOperationContext detects the operation type and extracts full context
func ExtractOperationContext(data []byte, args *cli.Args) *ActionContext {
	// Try to parse as git commit
	if gitCtx := ParseGitCommitObject(data); gitCtx != nil {
		// Extract first line of commit message for description
		firstLine := gitCtx.Message
		if idx := strings.Index(firstLine, "\n"); idx > 0 {
			firstLine = firstLine[:idx]
		}
		if len(firstLine) > 72 {
			firstLine = firstLine[:72] + "..."
		}

		return &ActionContext{
			Title:       "Sign commit?",
			Description: firstLine,
			OperationContext: &GPGOperationContext{
				IsGitCommit: true,
				GitContext:  gitCtx,
			},
		}
	}

	// General GPG operation
	generalCtx := BuildGeneralContext(args, data)

	return &ActionContext{
		Title:       getGeneralActionTitle(args),
		Description: getGeneralDescription(args, data),
		OperationContext: &GPGOperationContext{
			IsGitCommit:    false,
			GeneralContext: generalCtx,
		},
	}
}

// getGeneralActionTitle returns the action title for general GPG operations
func getGeneralActionTitle(args *cli.Args) string {
	switch args.Mode {
	case cli.ModeDetach:
		return "Create detached signature?"
	case cli.ModeSign:
		return "Sign data?"
	default:
		return "Sign with GPG?"
	}
}

// getGeneralDescription returns a short description for general GPG operations
func getGeneralDescription(args *cli.Args, data []byte) string {
	if args.InputFile != "" && args.InputFile != "-" {
		return args.InputFile
	}
	return formatBytes(len(data)) + " from stdin"
}

// formatBytes formats byte count in human-readable form
func formatBytes(bytes int) string {
	if bytes < 1024 {
		return strconv.Itoa(bytes) + " bytes"
	} else if bytes < 1024*1024 {
		return strconv.FormatFloat(float64(bytes)/1024, 'f', 1, 64) + " KB"
	}
	return strconv.FormatFloat(float64(bytes)/(1024*1024), 'f', 1, 64) + " MB"
}
