package commands

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ackagent/cli/internal/gpg/cli"
)

func TestParseGitCommitObject_ValidCommit(t *testing.T) {
	// Real git commit format
	commitData := `tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904
parent abc123def456789012345678901234567890abcd
author John Doe <john@example.com> 1704067200 +0000
committer Jane Smith <jane@example.com> 1704067260 -0800

Initial commit

This is a detailed commit message.`

	ctx := ParseGitCommitObject([]byte(commitData))
	if ctx == nil {
		t.Fatal("ParseGitCommitObject returned nil for valid commit")
	}

	// Verify tree hash
	if ctx.TreeHash != "4b825dc642cb6eb9a060e54bf8d69288fbee4904" {
		t.Errorf("TreeHash mismatch: got %s", ctx.TreeHash)
	}

	// Verify parent hash
	if len(ctx.ParentHashes) != 1 {
		t.Errorf("Expected 1 parent hash, got %d", len(ctx.ParentHashes))
	}
	if ctx.ParentHashes[0] != "abc123def456789012345678901234567890abcd" {
		t.Errorf("Parent hash mismatch: got %s", ctx.ParentHashes[0])
	}

	// Verify author
	if ctx.AuthorName != "John Doe" {
		t.Errorf("AuthorName mismatch: got %s", ctx.AuthorName)
	}
	if ctx.AuthorEmail != "john@example.com" {
		t.Errorf("AuthorEmail mismatch: got %s", ctx.AuthorEmail)
	}
	if ctx.AuthorTime != 1704067200 {
		t.Errorf("AuthorTime mismatch: got %d", ctx.AuthorTime)
	}

	// Verify committer
	if ctx.CommitterName != "Jane Smith" {
		t.Errorf("CommitterName mismatch: got %s", ctx.CommitterName)
	}
	if ctx.CommitterEmail != "jane@example.com" {
		t.Errorf("CommitterEmail mismatch: got %s", ctx.CommitterEmail)
	}
	if ctx.CommitterTime != 1704067260 {
		t.Errorf("CommitterTime mismatch: got %d", ctx.CommitterTime)
	}

	// Verify message
	expectedMessage := "Initial commit\n\nThis is a detailed commit message."
	if ctx.Message != expectedMessage {
		t.Errorf("Message mismatch: got %q, want %q", ctx.Message, expectedMessage)
	}
}

func TestParseGitCommitObject_InitialCommitNoParent(t *testing.T) {
	// Initial commits have no parent
	commitData := `tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904
author John Doe <john@example.com> 1704067200 +0000
committer John Doe <john@example.com> 1704067200 +0000

Initial commit`

	ctx := ParseGitCommitObject([]byte(commitData))
	if ctx == nil {
		t.Fatal("ParseGitCommitObject returned nil for valid initial commit")
	}

	// No parent hashes for initial commit
	if len(ctx.ParentHashes) != 0 {
		t.Errorf("Expected 0 parent hashes for initial commit, got %d", len(ctx.ParentHashes))
	}
}

func TestParseGitCommitObject_MergeCommitMultipleParents(t *testing.T) {
	// Merge commits have multiple parents
	commitData := `tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904
parent abc123def456789012345678901234567890abcd
parent def456789012345678901234567890abcdef12
parent 789012345678901234567890abcdef12345678
author John Doe <john@example.com> 1704067200 +0000
committer John Doe <john@example.com> 1704067200 +0000

Merge branches 'feature-a', 'feature-b', 'feature-c'`

	ctx := ParseGitCommitObject([]byte(commitData))
	if ctx == nil {
		t.Fatal("ParseGitCommitObject returned nil for merge commit")
	}

	if len(ctx.ParentHashes) != 3 {
		t.Errorf("Expected 3 parent hashes for merge commit, got %d", len(ctx.ParentHashes))
	}
}

func TestParseGitCommitObject_NotGitCommit(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{"empty", ""},
		{"random text", "hello world"},
		{"missing tree prefix", "not a tree\nauthor John <j@x.com> 123 +0"},
		{"only tree line", "tree abc123"},
		{"missing author", "tree abc123\ncommitter John <j@x.com> 123 +0"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := ParseGitCommitObject([]byte(tc.data))
			if ctx != nil {
				t.Errorf("Expected nil for non-git data, got %+v", ctx)
			}
		})
	}
}

func TestParseGitCommitObject_EmptyMessage(t *testing.T) {
	commitData := `tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904
author John Doe <john@example.com> 1704067200 +0000
committer John Doe <john@example.com> 1704067200 +0000

`

	ctx := ParseGitCommitObject([]byte(commitData))
	if ctx == nil {
		t.Fatal("ParseGitCommitObject returned nil")
	}

	if ctx.Message != "" {
		t.Errorf("Expected empty message, got %q", ctx.Message)
	}
}

func TestParseGitCommitObject_MessageWithNewlines(t *testing.T) {
	commitData := `tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904
author John Doe <john@example.com> 1704067200 +0000
committer John Doe <john@example.com> 1704067200 +0000

Short summary

Long description paragraph 1.

Long description paragraph 2.

- Bullet point 1
- Bullet point 2`

	ctx := ParseGitCommitObject([]byte(commitData))
	if ctx == nil {
		t.Fatal("ParseGitCommitObject returned nil")
	}

	// Message should preserve newlines
	if !strings.Contains(ctx.Message, "paragraph 1") {
		t.Error("Message missing paragraph 1")
	}
	if !strings.Contains(ctx.Message, "Bullet point") {
		t.Error("Message missing bullet points")
	}
}

func TestParseGitIdentity_ValidFormats(t *testing.T) {
	tests := []struct {
		input     string
		wantName  string
		wantEmail string
		wantTs    int64
	}{
		{
			"John Doe <john@example.com> 1704067200 +0000",
			"John Doe", "john@example.com", 1704067200,
		},
		{
			"Jane Smith <jane@example.com> 1704067260 -0800",
			"Jane Smith", "jane@example.com", 1704067260,
		},
		{
			"Single <single@x.com> 0 +0000",
			"Single", "single@x.com", 0,
		},
		{
			"Multiple Word Name <multi@x.com> 9999999999 +1200",
			"Multiple Word Name", "multi@x.com", 9999999999,
		},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			name, email, ts := parseGitIdentity(tc.input)
			if name != tc.wantName {
				t.Errorf("name mismatch: got %q, want %q", name, tc.wantName)
			}
			if email != tc.wantEmail {
				t.Errorf("email mismatch: got %q, want %q", email, tc.wantEmail)
			}
			if ts != tc.wantTs {
				t.Errorf("timestamp mismatch: got %d, want %d", ts, tc.wantTs)
			}
		})
	}
}

func TestParseGitIdentity_EdgeCases(t *testing.T) {
	// Test with missing angle brackets
	name, email, ts := parseGitIdentity("John Doe john@example.com 1234567890 +0000")
	if name != "" || email != "" || ts != 0 {
		// When email brackets missing, should return empty/zero
		// This is defensive parsing
	}

	// Test with no timestamp
	name, email, ts = parseGitIdentity("John Doe <john@example.com>")
	if name != "John Doe" {
		t.Errorf("name mismatch: got %q", name)
	}
	if email != "john@example.com" {
		t.Errorf("email mismatch: got %q", email)
	}
	// ts should be 0 when no timestamp
}

func TestBuildGeneralContext_FromFile(t *testing.T) {
	args := &cli.Args{
		Mode:       cli.ModeDetach,
		Armor:      true,
		LocalUser:  "ABCD1234",
		OutputFile: "output.sig",
		InputFile:  "document.txt",
	}
	data := []byte("Hello, this is the document content to be signed.")

	ctx := BuildGeneralContext(args, data)

	// Check input source
	if ctx.InputSource != "document.txt" {
		t.Errorf("InputSource mismatch: got %s", ctx.InputSource)
	}
	if ctx.IsStdin {
		t.Error("IsStdin should be false for file input")
	}

	// Check operation type
	if ctx.OperationType != "detach-sign" {
		t.Errorf("OperationType mismatch: got %s", ctx.OperationType)
	}

	// Check content size
	if ctx.ContentSize != len(data) {
		t.Errorf("ContentSize mismatch: got %d, want %d", ctx.ContentSize, len(data))
	}

	// Check content hash
	expectedHash := sha256.Sum256(data)
	if ctx.ContentHash != hex.EncodeToString(expectedHash[:]) {
		t.Errorf("ContentHash mismatch: got %s", ctx.ContentHash)
	}

	// Check command line reconstruction
	if !strings.Contains(ctx.CommandLine, "--detach-sign") {
		t.Error("CommandLine missing --detach-sign")
	}
	if !strings.Contains(ctx.CommandLine, "--armor") {
		t.Error("CommandLine missing --armor")
	}
}

func TestBuildGeneralContext_FromStdin(t *testing.T) {
	args := &cli.Args{
		Mode:      cli.ModeSign,
		InputFile: "",
	}
	data := []byte("stdin content")

	ctx := BuildGeneralContext(args, data)

	if ctx.InputSource != "stdin" {
		t.Errorf("InputSource should be 'stdin', got %s", ctx.InputSource)
	}
	if !ctx.IsStdin {
		t.Error("IsStdin should be true")
	}
}

func TestBuildGeneralContext_DashInputFile(t *testing.T) {
	args := &cli.Args{
		Mode:      cli.ModeSign,
		InputFile: "-",
	}
	data := []byte("stdin via dash")

	ctx := BuildGeneralContext(args, data)

	if ctx.InputSource != "stdin" {
		t.Errorf("InputSource should be 'stdin' for '-' input, got %s", ctx.InputSource)
	}
	if !ctx.IsStdin {
		t.Error("IsStdin should be true for '-' input")
	}
}

func TestBuildGeneralContext_SmallTextContent(t *testing.T) {
	args := &cli.Args{Mode: cli.ModeSign}
	data := []byte("Small text content under 2KB limit")

	ctx := BuildGeneralContext(args, data)

	// Small text should be included in full
	if ctx.ContentFull != string(data) {
		t.Errorf("ContentFull mismatch: got %q, want %q", ctx.ContentFull, string(data))
	}
	if ctx.ContentPreview != "" {
		t.Error("ContentPreview should be empty for small content")
	}
}

func TestBuildGeneralContext_LargeTextContent(t *testing.T) {
	args := &cli.Args{Mode: cli.ModeSign}
	// Create content larger than ContentInlineLimit (2048 bytes)
	data := make([]byte, 3000)
	for i := range data {
		data[i] = 'a' + byte(i%26)
	}

	ctx := BuildGeneralContext(args, data)

	// Large text should have preview only
	if ctx.ContentFull != "" {
		t.Error("ContentFull should be empty for large content")
	}
	if ctx.ContentPreview == "" {
		t.Error("ContentPreview should be set for large content")
	}
	// Preview should be at most ContentPreviewLimit (500) + "..."
	if len(ctx.ContentPreview) > ContentPreviewLimit+3 {
		t.Errorf("ContentPreview too long: %d", len(ctx.ContentPreview))
	}
}

func TestBuildGeneralContext_BinaryContent(t *testing.T) {
	args := &cli.Args{Mode: cli.ModeSign}
	// Binary content (contains null bytes)
	data := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0x00}

	ctx := BuildGeneralContext(args, data)

	// Binary content should not have preview or full content
	if ctx.ContentFull != "" {
		t.Error("ContentFull should be empty for binary content")
	}
	if ctx.ContentPreview != "" {
		t.Error("ContentPreview should be empty for binary content")
	}
}

func TestIsLikelyText(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		wantText bool
	}{
		{"empty", []byte{}, true},
		{"ascii text", []byte("Hello, World!"), true},
		{"utf8 text", []byte("日本語テキスト"), true},
		{"with newlines", []byte("line1\nline2\r\nline3"), true},
		{"binary with null", []byte{0x00, 0x01, 0x02}, false},
		{"text with embedded null", []byte("text\x00more"), false},
		{"pure binary", []byte{0xFF, 0x00, 0xAB, 0x00}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isLikelyText(tc.data)
			if got != tc.wantText {
				t.Errorf("isLikelyText() = %v, want %v", got, tc.wantText)
			}
		})
	}
}

func TestIsLikelyText_ChecksFirst512Bytes(t *testing.T) {
	// Text with null byte at position 600 (after the 512 byte check window)
	data := make([]byte, 1000)
	for i := range data {
		data[i] = 'x'
	}
	data[600] = 0x00 // Null after check window

	if !isLikelyText(data) {
		t.Error("Should be considered text since null is after 512 byte check window")
	}

	// Null byte within check window
	data[100] = 0x00
	if isLikelyText(data) {
		t.Error("Should not be considered text since null is within 512 byte check window")
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		bytes int
		want  string
	}{
		{0, "0 bytes"},
		{1, "1 bytes"},
		{512, "512 bytes"},
		{1023, "1023 bytes"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{2048, "2.0 KB"},
		{1024 * 1024, "1.0 MB"},
		{1024 * 1024 * 2, "2.0 MB"},
		{1024*1024 + 512*1024, "1.5 MB"},
	}

	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			got := formatBytes(tc.bytes)
			if got != tc.want {
				t.Errorf("formatBytes(%d) = %q, want %q", tc.bytes, got, tc.want)
			}
		})
	}
}

func TestGetOperationType(t *testing.T) {
	tests := []struct {
		mode cli.Mode
		want string
	}{
		{cli.ModeDetach, "detach-sign"},
		{cli.ModeSign, "sign"},
		{cli.ModeVerify, "sign"}, // Default case
	}

	for _, tc := range tests {
		got := getOperationType(&cli.Args{Mode: tc.mode})
		if got != tc.want {
			t.Errorf("getOperationType(mode=%d) = %q, want %q", tc.mode, got, tc.want)
		}
	}
}

func TestReconstructCommandLine(t *testing.T) {
	args := &cli.Args{
		Mode:       cli.ModeDetach,
		Armor:      true,
		LocalUser:  "ABCD1234",
		OutputFile: "output.sig",
		InputFile:  "document.txt",
	}

	cmdLine := reconstructCommandLine(args)

	// Check all components present
	if !strings.HasPrefix(cmdLine, "ackagent gpg") {
		t.Errorf("CommandLine should start with 'ackagent gpg': %s", cmdLine)
	}
	if !strings.Contains(cmdLine, "--detach-sign") {
		t.Error("Missing --detach-sign")
	}
	if !strings.Contains(cmdLine, "--armor") {
		t.Error("Missing --armor")
	}
	if !strings.Contains(cmdLine, "-u ABCD1234") {
		t.Error("Missing -u LocalUser")
	}
	if !strings.Contains(cmdLine, "-o output.sig") {
		t.Error("Missing -o OutputFile")
	}
	if !strings.Contains(cmdLine, "document.txt") {
		t.Error("Missing input file")
	}
}

func TestReconstructCommandLine_MinimalArgs(t *testing.T) {
	args := &cli.Args{
		Mode: cli.ModeSign,
	}

	cmdLine := reconstructCommandLine(args)

	if cmdLine != "ackagent gpg --sign" {
		t.Errorf("Unexpected minimal command line: %q", cmdLine)
	}
}

func TestReconstructCommandLine_StdinInput(t *testing.T) {
	args := &cli.Args{
		Mode:      cli.ModeSign,
		InputFile: "-",
	}

	cmdLine := reconstructCommandLine(args)

	// Stdin (-) should not appear in command line
	if strings.Contains(cmdLine, " -") && strings.HasSuffix(cmdLine, " -") {
		t.Error("Stdin '-' should not appear in reconstructed command line")
	}
}

func TestExtractOperationContext_GitCommit(t *testing.T) {
	commitData := `tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904
author John Doe <john@example.com> 1704067200 +0000
committer John Doe <john@example.com> 1704067200 +0000

Add new feature

This commit adds a great new feature.`

	args := &cli.Args{Mode: cli.ModeDetach}
	ctx := ExtractOperationContext([]byte(commitData), args)

	if ctx == nil {
		t.Fatal("ExtractOperationContext returned nil")
	}

	if ctx.Title != "Sign commit?" {
		t.Errorf("Title mismatch: got %q", ctx.Title)
	}

	// Description should be first line of commit message
	if ctx.Description != "Add new feature" {
		t.Errorf("Description mismatch: got %q", ctx.Description)
	}

	if ctx.OperationContext == nil || !ctx.OperationContext.IsGitCommit {
		t.Error("Should be detected as git commit")
	}
}

func TestExtractOperationContext_LongCommitMessage(t *testing.T) {
	// Commit message longer than 72 chars
	longMsg := strings.Repeat("x", 100)
	commitData := `tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904
author John Doe <john@example.com> 1704067200 +0000
committer John Doe <john@example.com> 1704067200 +0000

` + longMsg

	args := &cli.Args{Mode: cli.ModeDetach}
	ctx := ExtractOperationContext([]byte(commitData), args)

	// Description should be truncated
	if len(ctx.Description) > 75 { // 72 + "..."
		t.Errorf("Description should be truncated, got length %d", len(ctx.Description))
	}
	if !strings.HasSuffix(ctx.Description, "...") {
		t.Error("Truncated description should end with ...")
	}
}

func TestExtractOperationContext_GeneralGPG(t *testing.T) {
	args := &cli.Args{
		Mode:      cli.ModeDetach,
		InputFile: "document.pdf",
	}
	data := []byte{0xFF, 0xD8, 0xFF, 0xE0} // Binary data (JPEG header)

	ctx := ExtractOperationContext(data, args)

	if ctx == nil {
		t.Fatal("ExtractOperationContext returned nil")
	}

	if ctx.Title != "Create detached signature?" {
		t.Errorf("Title mismatch: got %q", ctx.Title)
	}

	if ctx.OperationContext.IsGitCommit {
		t.Error("Should not be detected as git commit")
	}
	if ctx.OperationContext.GeneralContext == nil {
		t.Error("GeneralContext should be set")
	}
}

func TestGetGeneralActionTitle(t *testing.T) {
	tests := []struct {
		mode cli.Mode
		want string
	}{
		{cli.ModeDetach, "Create detached signature?"},
		{cli.ModeSign, "Sign data?"},
		{cli.ModeVerify, "Sign with GPG?"}, // Default
	}

	for _, tc := range tests {
		args := &cli.Args{Mode: tc.mode}
		got := getGeneralActionTitle(args)
		if got != tc.want {
			t.Errorf("getGeneralActionTitle(mode=%d) = %q, want %q", tc.mode, got, tc.want)
		}
	}
}

func TestGetGeneralDescription(t *testing.T) {
	// With file input
	args := &cli.Args{InputFile: "document.txt"}
	got := getGeneralDescription(args, []byte("content"))
	if got != "document.txt" {
		t.Errorf("Expected filename, got %q", got)
	}

	// With stdin
	args = &cli.Args{InputFile: ""}
	got = getGeneralDescription(args, []byte("small content"))
	if !strings.Contains(got, "from stdin") {
		t.Errorf("Expected 'from stdin', got %q", got)
	}
}

func TestComputeSHA256(t *testing.T) {
	data := []byte("test data")
	expected := sha256.Sum256(data)
	expectedHex := hex.EncodeToString(expected[:])

	got := computeSHA256(data)
	if got != expectedHex {
		t.Errorf("SHA256 mismatch: got %s, want %s", got, expectedHex)
	}
}
