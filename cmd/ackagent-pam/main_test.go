package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:     "ackagent-pam",
		Short:   "AckAgent PAM authentication CLI",
		Version: version,
	}
	rootCmd.AddCommand(keygenCmd())
	rootCmd.AddCommand(exportPublicCmd())
	rootCmd.AddCommand(fingerprintCmd())
	rootCmd.AddCommand(testCmd())
	return rootCmd
}

func findSubcommand(root *cobra.Command, use string) *cobra.Command {
	for _, sub := range root.Commands() {
		if sub.Use == use {
			return sub
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Root command tests
// ---------------------------------------------------------------------------

func TestRootCommand_Use(t *testing.T) {
	root := newTestRootCmd()
	assert.Equal(t, "ackagent-pam", root.Use)
}

func TestRootCommand_Version(t *testing.T) {
	root := newTestRootCmd()
	assert.Equal(t, version, root.Version)
}

func TestRootCommand_SubcommandCount(t *testing.T) {
	root := newTestRootCmd()
	assert.Len(t, root.Commands(), 4, "root should have 4 subcommands")
}

// ---------------------------------------------------------------------------
// keygen subcommand tests
// ---------------------------------------------------------------------------

func TestKeygen_Exists(t *testing.T) {
	root := newTestRootCmd()
	cmd := findSubcommand(root, "keygen")
	require.NotNil(t, cmd, "keygen subcommand should exist")
}

func TestKeygen_Use(t *testing.T) {
	root := newTestRootCmd()
	cmd := findSubcommand(root, "keygen")
	require.NotNil(t, cmd)
	assert.Equal(t, "keygen", cmd.Use)
}

func TestKeygen_OrgFlagRequired(t *testing.T) {
	root := newTestRootCmd()
	cmd := findSubcommand(root, "keygen")
	require.NotNil(t, cmd)

	f := cmd.Flags().Lookup("org")
	require.NotNil(t, f, "--org flag should exist")

	annotations := f.Annotations
	_, isRequired := annotations[cobra.BashCompOneRequiredFlag]
	assert.True(t, isRequired, "--org flag should be required")
}

func TestKeygen_OutputDefaultsDot(t *testing.T) {
	root := newTestRootCmd()
	cmd := findSubcommand(root, "keygen")
	require.NotNil(t, cmd)

	f := cmd.Flags().Lookup("output")
	require.NotNil(t, f, "--output flag should exist")
	assert.Equal(t, ".", f.DefValue)
}

func TestKeygen_NameDefault(t *testing.T) {
	root := newTestRootCmd()
	cmd := findSubcommand(root, "keygen")
	require.NotNil(t, cmd)

	f := cmd.Flags().Lookup("name")
	require.NotNil(t, f, "--name flag should exist")
	assert.Equal(t, "PAM Key", f.DefValue)
}

// ---------------------------------------------------------------------------
// export-public subcommand tests
// ---------------------------------------------------------------------------

func TestExportPublic_Exists(t *testing.T) {
	root := newTestRootCmd()
	cmd := findSubcommand(root, "export-public")
	require.NotNil(t, cmd, "export-public subcommand should exist")
}

func TestExportPublic_Use(t *testing.T) {
	root := newTestRootCmd()
	cmd := findSubcommand(root, "export-public")
	require.NotNil(t, cmd)
	assert.Equal(t, "export-public", cmd.Use)
}

func TestExportPublic_KeyFlagRequired(t *testing.T) {
	root := newTestRootCmd()
	cmd := findSubcommand(root, "export-public")
	require.NotNil(t, cmd)

	f := cmd.Flags().Lookup("key")
	require.NotNil(t, f, "--key flag should exist")

	annotations := f.Annotations
	_, isRequired := annotations[cobra.BashCompOneRequiredFlag]
	assert.True(t, isRequired, "--key flag should be required")
}

func TestExportPublic_FormatDefault(t *testing.T) {
	root := newTestRootCmd()
	cmd := findSubcommand(root, "export-public")
	require.NotNil(t, cmd)

	f := cmd.Flags().Lookup("format")
	require.NotNil(t, f, "--format flag should exist")
	assert.Equal(t, "base64", f.DefValue)
}

// ---------------------------------------------------------------------------
// fingerprint subcommand tests
// ---------------------------------------------------------------------------

func TestFingerprint_Exists(t *testing.T) {
	root := newTestRootCmd()
	cmd := findSubcommand(root, "fingerprint")
	require.NotNil(t, cmd, "fingerprint subcommand should exist")
}

func TestFingerprint_Use(t *testing.T) {
	root := newTestRootCmd()
	cmd := findSubcommand(root, "fingerprint")
	require.NotNil(t, cmd)
	assert.Equal(t, "fingerprint", cmd.Use)
}

func TestFingerprint_KeyFlagRequired(t *testing.T) {
	root := newTestRootCmd()
	cmd := findSubcommand(root, "fingerprint")
	require.NotNil(t, cmd)

	f := cmd.Flags().Lookup("key")
	require.NotNil(t, f, "--key flag should exist")

	annotations := f.Annotations
	_, isRequired := annotations[cobra.BashCompOneRequiredFlag]
	assert.True(t, isRequired, "--key flag should be required")
}

// ---------------------------------------------------------------------------
// test subcommand tests
// ---------------------------------------------------------------------------

func TestTestCmd_Exists(t *testing.T) {
	root := newTestRootCmd()
	cmd := findSubcommand(root, "test")
	require.NotNil(t, cmd, "test subcommand should exist")
}

func TestTestCmd_Use(t *testing.T) {
	root := newTestRootCmd()
	cmd := findSubcommand(root, "test")
	require.NotNil(t, cmd)
	assert.Equal(t, "test", cmd.Use)
}

func TestTestCmd_UserFlagRequired(t *testing.T) {
	root := newTestRootCmd()
	cmd := findSubcommand(root, "test")
	require.NotNil(t, cmd)

	f := cmd.Flags().Lookup("user")
	require.NotNil(t, f, "--user flag should exist")

	annotations := f.Annotations
	_, isRequired := annotations[cobra.BashCompOneRequiredFlag]
	assert.True(t, isRequired, "--user flag should be required")
}

func TestTestCmd_ServiceDefault(t *testing.T) {
	root := newTestRootCmd()
	cmd := findSubcommand(root, "test")
	require.NotNil(t, cmd)

	f := cmd.Flags().Lookup("service")
	require.NotNil(t, f, "--service flag should exist")
	assert.Equal(t, "pam-test", f.DefValue)
}

func TestTestCmd_ConfigDefault(t *testing.T) {
	root := newTestRootCmd()
	cmd := findSubcommand(root, "test")
	require.NotNil(t, cmd)

	f := cmd.Flags().Lookup("config")
	require.NotNil(t, f, "--config flag should exist")
	assert.Equal(t, "/etc/ackagent/pam.conf", f.DefValue)
}

// ---------------------------------------------------------------------------
// Functional test: keygen creates a valid key file
// ---------------------------------------------------------------------------

func TestKeygen_CreatesKeyFile(t *testing.T) {
	tmpDir := t.TempDir()
	root := newTestRootCmd()
	root.SetArgs([]string{"keygen", "--org", "test-org", "--output", tmpDir})
	err := root.Execute()
	require.NoError(t, err)

	// Verify key file was created
	keyPath := filepath.Join(tmpDir, "org.key")
	_, err = os.Stat(keyPath)
	require.NoError(t, err, "org.key should be created")

	// Verify it's valid PEM containing a PKCS8 private key
	data, err := os.ReadFile(keyPath)
	require.NoError(t, err)

	block, _ := pem.Decode(data)
	require.NotNil(t, block, "file should contain a PEM block")
	assert.Equal(t, "PRIVATE KEY", block.Type)

	// Verify the key can be parsed as PKCS8
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(t, err, "key should be valid PKCS8")
	require.NotNil(t, key)
}

func TestKeygen_KeyFilePermissions(t *testing.T) {
	tmpDir := t.TempDir()
	root := newTestRootCmd()
	root.SetArgs([]string{"keygen", "--org", "test-org", "--output", tmpDir})
	err := root.Execute()
	require.NoError(t, err)

	keyPath := filepath.Join(tmpDir, "org.key")
	info, err := os.Stat(keyPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm(),
		"private key should have 0600 permissions")
}

func TestKeygen_CustomName(t *testing.T) {
	tmpDir := t.TempDir()
	root := newTestRootCmd()
	root.SetArgs([]string{"keygen", "--org", "test-org", "--output", tmpDir, "--name", "Custom Key"})
	err := root.Execute()
	require.NoError(t, err)

	keyPath := filepath.Join(tmpDir, "org.key")
	_, err = os.Stat(keyPath)
	require.NoError(t, err, "key file should exist even with custom name")
}

func generateTestKey(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	root := newTestRootCmd()
	root.SetArgs([]string{"keygen", "--org", "test-org", "--output", tmpDir})
	err := root.Execute()
	require.NoError(t, err)
	return filepath.Join(tmpDir, "org.key")
}

func TestExportPublic_Base64(t *testing.T) {
	keyPath := generateTestKey(t)

	root := newTestRootCmd()
	root.SetArgs([]string{"export-public", "--key", keyPath, "--format", "base64"})
	err := root.Execute()
	require.NoError(t, err)
}

func TestExportPublic_PEM(t *testing.T) {
	keyPath := generateTestKey(t)

	root := newTestRootCmd()
	root.SetArgs([]string{"export-public", "--key", keyPath, "--format", "pem"})
	err := root.Execute()
	require.NoError(t, err)
}

func TestExportPublic_InvalidFormat(t *testing.T) {
	keyPath := generateTestKey(t)

	root := newTestRootCmd()
	root.SetArgs([]string{"export-public", "--key", keyPath, "--format", "xml"})
	err := root.Execute()
	assert.Error(t, err, "invalid format should return error")
}

func TestExportPublic_MissingKey(t *testing.T) {
	root := newTestRootCmd()
	root.SetArgs([]string{"export-public", "--key", "/nonexistent/path.key"})
	err := root.Execute()
	assert.Error(t, err, "missing key file should return error")
}

func TestFingerprint_ValidKey(t *testing.T) {
	keyPath := generateTestKey(t)

	root := newTestRootCmd()
	root.SetArgs([]string{"fingerprint", "--key", keyPath})
	err := root.Execute()
	require.NoError(t, err)
}

func TestFingerprint_MissingKey(t *testing.T) {
	root := newTestRootCmd()
	root.SetArgs([]string{"fingerprint", "--key", "/nonexistent/path.key"})
	err := root.Execute()
	assert.Error(t, err, "missing key file should return error")
}

func TestKeygen_MissingOrgFlag(t *testing.T) {
	root := newTestRootCmd()
	root.SetArgs([]string{"keygen"})
	err := root.Execute()
	assert.Error(t, err, "missing --org should return error")
}
