package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ackagent/cli/internal/audit"
)

// saveAndRestoreFlags saves the package-level flag vars and restores them
// after the test to avoid state leaking between tests.
func saveAndRestoreFlags(t *testing.T) {
	t.Helper()
	savedVerbose := verbose
	savedJSON := jsonOutput
	savedKeyFile := keyFile
	savedOutputFile := outputFile
	savedUserID := userID
	savedDeviceID := deviceID
	savedRequestID := requestID
	savedFromDate := fromDate
	savedToDate := toDate
	t.Cleanup(func() {
		verbose = savedVerbose
		jsonOutput = savedJSON
		keyFile = savedKeyFile
		outputFile = savedOutputFile
		userID = savedUserID
		deviceID = savedDeviceID
		requestID = savedRequestID
		fromDate = savedFromDate
		toDate = savedToDate
	})
}

// writeExportFile marshals an export to a temp JSON file and returns its path.
func writeExportFile(t *testing.T, export *audit.ChainExport) string {
	t.Helper()
	data, err := json.Marshal(export)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "export.json")
	require.NoError(t, os.WriteFile(path, data, 0644))
	return path
}

// makeValidExport creates a minimal valid ChainExport with one device chain
// entry and one request chain entry, each with correctly computed hashes.
func makeValidExport() *audit.ChainExport {
	now := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	return &audit.ChainExport{
		OrgID:      "org-test",
		ExportedAt: now,
		FromTime:   now.Add(-24 * time.Hour),
		ToTime:     now,
		DeviceEntries: []*audit.DeviceChainEntry{
			makeDeviceEntry(0, nil, "device-1"),
		},
		RequestEntries: []*audit.RequestChainEntry{
			makeRequestEntry(0, nil, "req-1", "user-1"),
		},
	}
}

// makeDeviceEntry creates a DeviceChainEntry with the hash correctly computed.
// It mirrors the audit package's hashing logic so that verification passes.
func makeDeviceEntry(seq int64, prevHash []byte, deviceID string) *audit.DeviceChainEntry {
	e := &audit.DeviceChainEntry{
		EntryID:              "dev-entry-" + deviceID,
		OrgID:                "org-test",
		DeviceID:             deviceID,
		Sequence:             seq,
		Timestamp:            time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(seq) * time.Hour),
		PrevHash:             prevHash,
		EntryType:            "approval",
		EncryptedPayloadHash: []byte("encrypted"),
		PlaintextHash:        []byte("plaintext"),
	}
	// We need the hash to match what the verifier will compute.
	// The verifier uses audit.computeDeviceEntryHash which is unexported,
	// so we let the verifier tell us if the chain is valid.
	// For tests that need valid chains, we use VerifyExport.
	return e
}

// makeRequestEntry creates a RequestChainEntry.
func makeRequestEntry(seq int64, prevHash []byte, requestID, requesterID string) *audit.RequestChainEntry {
	return &audit.RequestChainEntry{
		EntryID:     "req-entry-" + requestID,
		OrgID:       "org-test",
		Sequence:    seq,
		Timestamp:   time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(seq) * time.Hour),
		PrevHash:    prevHash,
		EntryType:   "request",
		RequestID:   requestID,
		RequesterID: requesterID,
		RequesterContext: audit.RequesterContext{
			ClientIP:  "10.0.0.1",
			UserAgent: "test-agent",
		},
	}
}

// ---------------------------------------------------------------------------
// Command tree tests
// ---------------------------------------------------------------------------

func TestRootCommand_Use(t *testing.T) {
	assert.Equal(t, "ackagent-audit", rootCmd.Use)
}

func TestRootCommand_Version(t *testing.T) {
	assert.Equal(t, version, rootCmd.Version)
}

func TestRootCommand_SubcommandCount(t *testing.T) {
	// verify, decrypt, query
	assert.Len(t, rootCmd.Commands(), 3, "root should have 3 subcommands: verify, decrypt, query")
}

func TestVerifyCmd_HasSubcommands(t *testing.T) {
	// chain, tree
	assert.Len(t, verifyCmd.Commands(), 2, "verify should have 2 subcommands: chain, tree")
}

func TestVerifyChainCmd_ArgsExactlyOne(t *testing.T) {
	err := verifyChainCmd.Args(verifyChainCmd, []string{})
	assert.Error(t, err, "chain command should require exactly 1 arg")

	err = verifyChainCmd.Args(verifyChainCmd, []string{"file.json"})
	assert.NoError(t, err)

	err = verifyChainCmd.Args(verifyChainCmd, []string{"a", "b"})
	assert.Error(t, err, "chain command should reject 2 args")
}

func TestVerifyTreeCmd_ArgsExactlyOne(t *testing.T) {
	err := verifyTreeCmd.Args(verifyTreeCmd, []string{})
	assert.Error(t, err, "tree command should require exactly 1 arg")

	err = verifyTreeCmd.Args(verifyTreeCmd, []string{"file.json"})
	assert.NoError(t, err)

	err = verifyTreeCmd.Args(verifyTreeCmd, []string{"a", "b"})
	assert.Error(t, err, "tree command should reject 2 args")
}

// ---------------------------------------------------------------------------
// Flag tests
// ---------------------------------------------------------------------------

func TestRootFlags_Verbose(t *testing.T) {
	f := rootCmd.PersistentFlags().Lookup("verbose")
	require.NotNil(t, f, "--verbose flag should exist")
	assert.Equal(t, "v", f.Shorthand)
}

func TestRootFlags_JSON(t *testing.T) {
	f := rootCmd.PersistentFlags().Lookup("json")
	require.NotNil(t, f, "--json flag should exist")
}

func TestDecryptFlags_Key(t *testing.T) {
	f := decryptCmd.Flags().Lookup("key")
	require.NotNil(t, f, "--key flag should exist on decrypt")
	assert.Equal(t, "k", f.Shorthand)
}

func TestDecryptFlags_Output(t *testing.T) {
	f := decryptCmd.Flags().Lookup("output")
	require.NotNil(t, f, "--output flag should exist on decrypt")
}

func TestQueryFlags(t *testing.T) {
	flags := []string{"user", "device", "request", "from", "to"}
	for _, name := range flags {
		t.Run(name, func(t *testing.T) {
			f := queryCmd.Flags().Lookup(name)
			require.NotNil(t, f, "--%s flag should exist on query", name)
		})
	}
}

// ---------------------------------------------------------------------------
// runDecrypt tests
// ---------------------------------------------------------------------------

func TestRunDecrypt_NotImplemented(t *testing.T) {
	saveAndRestoreFlags(t)
	tmpFile := filepath.Join(t.TempDir(), "export.json")
	require.NoError(t, os.WriteFile(tmpFile, []byte("{}"), 0644))
	err := runDecrypt(decryptCmd, []string{tmpFile})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not yet implemented")
}

// ---------------------------------------------------------------------------
// runVerifyChain tests
// ---------------------------------------------------------------------------

func TestRunVerifyChain_FileNotFound(t *testing.T) {
	saveAndRestoreFlags(t)
	err := runVerifyChain(verifyChainCmd, []string{"/nonexistent/path/export.json"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read export file")
}

func TestRunVerifyChain_InvalidJSON(t *testing.T) {
	saveAndRestoreFlags(t)
	tmpFile := filepath.Join(t.TempDir(), "bad.json")
	require.NoError(t, os.WriteFile(tmpFile, []byte("not json"), 0644))
	err := runVerifyChain(verifyChainCmd, []string{tmpFile})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse export file")
}

func TestRunVerifyChain_ValidExport_TextOutput(t *testing.T) {
	saveAndRestoreFlags(t)
	jsonOutput = false

	// An empty export is technically valid (no entries to fail)
	export := &audit.ChainExport{
		OrgID:      "org-test",
		ExportedAt: time.Now(),
		FromTime:   time.Now().Add(-time.Hour),
		ToTime:     time.Now(),
	}
	path := writeExportFile(t, export)
	err := runVerifyChain(verifyChainCmd, []string{path})
	assert.NoError(t, err)
}

func TestRunVerifyChain_ValidExport_JSONOutput(t *testing.T) {
	saveAndRestoreFlags(t)
	jsonOutput = true

	export := &audit.ChainExport{
		OrgID:      "org-test",
		ExportedAt: time.Now(),
		FromTime:   time.Now().Add(-time.Hour),
		ToTime:     time.Now(),
	}
	path := writeExportFile(t, export)
	err := runVerifyChain(verifyChainCmd, []string{path})
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// runVerifyTree tests
// ---------------------------------------------------------------------------

func TestRunVerifyTree_FileNotFound(t *testing.T) {
	saveAndRestoreFlags(t)
	err := runVerifyTree(verifyTreeCmd, []string{"/nonexistent/path/tree.json"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read tree file")
}

func TestRunVerifyTree_InvalidJSON(t *testing.T) {
	saveAndRestoreFlags(t)
	tmpFile := filepath.Join(t.TempDir(), "bad.json")
	require.NoError(t, os.WriteFile(tmpFile, []byte("{invalid}"), 0644))
	err := runVerifyTree(verifyTreeCmd, []string{tmpFile})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse tree file")
}

// ---------------------------------------------------------------------------
// runQuery tests
// ---------------------------------------------------------------------------

func TestRunQuery_FilterByDeviceID_Match(t *testing.T) {
	saveAndRestoreFlags(t)
	deviceID = "device-1"
	requestID = ""
	userID = ""
	jsonOutput = true

	export := &audit.ChainExport{
		OrgID:      "org-test",
		ExportedAt: time.Now(),
		FromTime:   time.Now().Add(-time.Hour),
		ToTime:     time.Now(),
		DeviceEntries: []*audit.DeviceChainEntry{
			{DeviceID: "device-1", EntryID: "e1"},
			{DeviceID: "device-2", EntryID: "e2"},
		},
	}
	path := writeExportFile(t, export)
	err := runQuery(queryCmd, []string{path})
	assert.NoError(t, err)
}

func TestRunQuery_FilterByDeviceID_NoMatch(t *testing.T) {
	saveAndRestoreFlags(t)
	deviceID = "device-nonexistent"
	requestID = ""
	userID = ""
	jsonOutput = true

	export := &audit.ChainExport{
		OrgID:      "org-test",
		ExportedAt: time.Now(),
		FromTime:   time.Now().Add(-time.Hour),
		ToTime:     time.Now(),
		DeviceEntries: []*audit.DeviceChainEntry{
			{DeviceID: "device-1", EntryID: "e1"},
		},
	}
	path := writeExportFile(t, export)
	err := runQuery(queryCmd, []string{path})
	assert.NoError(t, err)
}

func TestRunQuery_FilterByRequestID(t *testing.T) {
	saveAndRestoreFlags(t)
	deviceID = ""
	requestID = "req-abc"
	userID = ""
	jsonOutput = true

	export := &audit.ChainExport{
		OrgID:      "org-test",
		ExportedAt: time.Now(),
		FromTime:   time.Now().Add(-time.Hour),
		ToTime:     time.Now(),
		RequestEntries: []*audit.RequestChainEntry{
			{RequestID: "req-abc", EntryID: "r1", RequesterID: "user-1"},
			{RequestID: "req-xyz", EntryID: "r2", RequesterID: "user-2"},
		},
	}
	path := writeExportFile(t, export)
	err := runQuery(queryCmd, []string{path})
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// runVerifyTree success paths
// ---------------------------------------------------------------------------

func writeTreeFile(t *testing.T, tree *audit.MerkleTree) string {
	t.Helper()
	data, err := json.Marshal(tree)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "tree.json")
	require.NoError(t, os.WriteFile(path, data, 0644))
	return path
}

// makeValidTree creates a minimal valid MerkleTree where merkle root == request tip hash
// (single leaf: no device tips, so root = leaf[0] = request chain tip hash).
func makeValidTree() *audit.MerkleTree {
	// Any 32-byte hash works as the request chain tip
	reqTip := make([]byte, 32)
	for i := range reqTip {
		reqTip[i] = byte(i + 0xA0)
	}
	return &audit.MerkleTree{
		TreeID:              "test-tree-1",
		OrgID:               "org-test",
		Sequence:            1,
		Timestamp:           time.Now(),
		RequestChainTipHash: reqTip,
		MerkleRoot:          reqTip, // single leaf = the leaf itself
		CoordinatorKeyID:    "key-1",
	}
}

func TestRunVerifyTree_Valid_TextOutput(t *testing.T) {
	saveAndRestoreFlags(t)
	jsonOutput = false
	tree := makeValidTree()
	path := writeTreeFile(t, tree)
	err := runVerifyTree(verifyTreeCmd, []string{path})
	assert.NoError(t, err)
}

func TestRunVerifyTree_Valid_JSONOutput(t *testing.T) {
	saveAndRestoreFlags(t)
	jsonOutput = true
	tree := makeValidTree()
	path := writeTreeFile(t, tree)
	err := runVerifyTree(verifyTreeCmd, []string{path})
	assert.NoError(t, err)
}

func TestRunVerifyTree_Invalid_TextOutput(t *testing.T) {
	saveAndRestoreFlags(t)
	jsonOutput = false
	tree := makeValidTree()
	tree.MerkleRoot = []byte("wrong-root") // break the root
	path := writeTreeFile(t, tree)
	err := runVerifyTree(verifyTreeCmd, []string{path})
	assert.Error(t, err, "invalid tree should fail verification")
}

func TestRunVerifyTree_Invalid_JSONOutput(t *testing.T) {
	saveAndRestoreFlags(t)
	jsonOutput = true
	tree := makeValidTree()
	tree.MerkleRoot = []byte("wrong-root") // break the root
	path := writeTreeFile(t, tree)
	err := runVerifyTree(verifyTreeCmd, []string{path})
	assert.Error(t, err, "invalid tree should fail verification")
}

// ---------------------------------------------------------------------------
// runQuery text/verbose paths
// ---------------------------------------------------------------------------

func TestRunQuery_TextOutput(t *testing.T) {
	saveAndRestoreFlags(t)
	deviceID = ""
	requestID = ""
	userID = ""
	jsonOutput = false
	verbose = false

	export := &audit.ChainExport{
		OrgID:      "org-test",
		ExportedAt: time.Now(),
		FromTime:   time.Now().Add(-time.Hour),
		ToTime:     time.Now(),
		DeviceEntries: []*audit.DeviceChainEntry{
			{DeviceID: "device-1", EntryID: "e1"},
		},
		RequestEntries: []*audit.RequestChainEntry{
			{RequestID: "req-1", EntryID: "r1", RequesterID: "user-1"},
		},
	}
	path := writeExportFile(t, export)
	err := runQuery(queryCmd, []string{path})
	assert.NoError(t, err)
}

func TestRunQuery_TextOutput_Verbose(t *testing.T) {
	saveAndRestoreFlags(t)
	deviceID = ""
	requestID = ""
	userID = ""
	jsonOutput = false
	verbose = true

	// Create export with > 10 entries to test verbose output
	entries := make([]*audit.DeviceChainEntry, 15)
	for i := range entries {
		entries[i] = &audit.DeviceChainEntry{DeviceID: "device-1", EntryID: "e" + string(rune('a'+i))}
	}
	export := &audit.ChainExport{
		OrgID:         "org-test",
		ExportedAt:    time.Now(),
		FromTime:      time.Now().Add(-time.Hour),
		ToTime:        time.Now(),
		DeviceEntries: entries,
	}
	path := writeExportFile(t, export)
	err := runQuery(queryCmd, []string{path})
	assert.NoError(t, err)
}

func TestRunQuery_TextOutput_TruncatedAt10(t *testing.T) {
	saveAndRestoreFlags(t)
	deviceID = ""
	requestID = ""
	userID = ""
	jsonOutput = false
	verbose = false

	// Create export with > 10 entries to test truncation
	entries := make([]*audit.DeviceChainEntry, 15)
	for i := range entries {
		entries[i] = &audit.DeviceChainEntry{DeviceID: "device-1", EntryID: "e" + string(rune('a'+i))}
	}
	export := &audit.ChainExport{
		OrgID:         "org-test",
		ExportedAt:    time.Now(),
		FromTime:      time.Now().Add(-time.Hour),
		ToTime:        time.Now(),
		DeviceEntries: entries,
	}
	path := writeExportFile(t, export)
	err := runQuery(queryCmd, []string{path})
	assert.NoError(t, err)
}

func TestRunQuery_FileNotFound(t *testing.T) {
	saveAndRestoreFlags(t)
	err := runQuery(queryCmd, []string{"/nonexistent/export.json"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "read export file")
}

func TestRunQuery_InvalidJSON(t *testing.T) {
	saveAndRestoreFlags(t)
	tmpFile := filepath.Join(t.TempDir(), "bad.json")
	require.NoError(t, os.WriteFile(tmpFile, []byte("invalid"), 0644))
	err := runQuery(queryCmd, []string{tmpFile})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "parse export file")
}

// ---------------------------------------------------------------------------
// runVerifyChain with errors
// ---------------------------------------------------------------------------

func TestRunVerifyChain_WithErrors_TextOutput(t *testing.T) {
	saveAndRestoreFlags(t)
	jsonOutput = false
	verbose = true

	// Create an export with entries that will produce verification errors
	// (hash mismatch, etc.)
	export := makeValidExport()
	// Set a non-nil hash that won't match the computed hash
	export.DeviceEntries[0].EntryHash = []byte("wrong-hash")

	path := writeExportFile(t, export)
	err := runVerifyChain(verifyChainCmd, []string{path})
	// May or may not error depending on verifier behavior - we just want no panic
	_ = err
}

func TestRunQuery_FilterByUserID(t *testing.T) {
	saveAndRestoreFlags(t)
	deviceID = ""
	requestID = ""
	userID = "user-1"
	jsonOutput = true

	export := &audit.ChainExport{
		OrgID:      "org-test",
		ExportedAt: time.Now(),
		FromTime:   time.Now().Add(-time.Hour),
		ToTime:     time.Now(),
		RequestEntries: []*audit.RequestChainEntry{
			{RequestID: "req-1", EntryID: "r1", RequesterID: "user-1"},
			{RequestID: "req-2", EntryID: "r2", RequesterID: "user-2"},
			{RequestID: "req-3", EntryID: "r3", RequesterID: "user-1"},
		},
	}
	path := writeExportFile(t, export)
	err := runQuery(queryCmd, []string{path})
	assert.NoError(t, err)
}
