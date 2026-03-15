package pam

import (
	"testing"

	protocol "github.com/ackagent/api/go/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPamAuthPayload_BasicFields(t *testing.T) {
	authCtx := &AuthContext{
		LocalUsername: "admin",
		PAMService:    "sshd",
		Hostname:      "server1.example.com",
		RemoteHost:    "192.168.1.100",
		TTY:           "/dev/pts/0",
		Timestamp:     1700000000,
	}

	payload := NewPamAuthPayload(authCtx, "admin@example.com")

	assert.Equal(t, protocol.PamAuth, payload.Type)
	assert.Equal(t, "admin", payload.LocalUsername)
	assert.Equal(t, "admin@example.com", payload.AckagentUser)
	assert.Equal(t, "sshd", payload.PamService)
}

func TestNewPamAuthPayload_DisplayFields(t *testing.T) {
	authCtx := &AuthContext{
		LocalUsername: "deploy",
		PAMService:    "sudo",
		Hostname:      "prod.example.com",
		RemoteHost:    "10.0.0.1",
	}

	payload := NewPamAuthPayload(authCtx, "deploy@example.com")

	require.NotNil(t, payload.Display)
	assert.Equal(t, "Login to prod.example.com", payload.Display.Title)
	require.NotNil(t, payload.Display.Subtitle)
	assert.Equal(t, "deploy via sudo", *payload.Display.Subtitle)
	require.NotNil(t, payload.Display.Icon)
	assert.Equal(t, "server.rack", *payload.Display.Icon)

	// Check display fields
	require.NotEmpty(t, payload.Display.Fields)
	// First field should be Local User
	assert.Equal(t, "Local User", payload.Display.Fields[0].Label)
	assert.Equal(t, "deploy", payload.Display.Fields[0].Value)
	// Second field should be Service
	assert.Equal(t, "Service", payload.Display.Fields[1].Label)
	assert.Equal(t, "sudo", payload.Display.Fields[1].Value)
}

func TestNewPamAuthPayload_WithRemoteHost(t *testing.T) {
	authCtx := &AuthContext{
		LocalUsername: "admin",
		PAMService:    "sshd",
		Hostname:      "server1",
		RemoteHost:    "192.168.1.100",
	}

	payload := NewPamAuthPayload(authCtx, "admin@example.com")

	// Should have Remote Host field
	require.NotNil(t, payload.RemoteHost)
	assert.Equal(t, "192.168.1.100", *payload.RemoteHost)

	// Check display has remote host
	foundRemoteHost := false
	for _, field := range payload.Display.Fields {
		if field.Label == "Remote Host" {
			foundRemoteHost = true
			assert.Equal(t, "192.168.1.100", field.Value)
			break
		}
	}
	assert.True(t, foundRemoteHost, "should have Remote Host display field")
}

func TestNewPamAuthPayload_WithSudoCommand(t *testing.T) {
	authCtx := &AuthContext{
		LocalUsername: "admin",
		PAMService:    "sudo",
		Hostname:      "server1",
		SudoCommand:   "/usr/bin/vim /etc/hosts",
	}

	payload := NewPamAuthPayload(authCtx, "admin@example.com")

	require.NotNil(t, payload.SudoCommand)
	assert.Equal(t, "/usr/bin/vim /etc/hosts", *payload.SudoCommand)

	// Check display has sudo command
	foundSudoCmd := false
	for _, field := range payload.Display.Fields {
		if field.Label == "Sudo Command" {
			foundSudoCmd = true
			assert.Equal(t, "/usr/bin/vim /etc/hosts", field.Value)
			break
		}
	}
	assert.True(t, foundSudoCmd, "should have Sudo Command display field")
}

func TestNewPamAuthPayload_NoOptionalFields(t *testing.T) {
	authCtx := &AuthContext{
		LocalUsername: "admin",
		PAMService:    "login",
		Hostname:      "server1",
		// No RemoteHost, no SudoCommand, no TTY, etc.
	}

	payload := NewPamAuthPayload(authCtx, "admin@example.com")

	assert.Nil(t, payload.RemoteHost)
	assert.Nil(t, payload.Tty)
	assert.Nil(t, payload.SudoCommand)
	assert.Nil(t, payload.SudoUser)
	assert.Nil(t, payload.SshClient)
	assert.Nil(t, payload.SshConnection)
	assert.Nil(t, payload.SshOriginalCommand)

	// Display should only have 2 base fields (Local User, Service)
	assert.Len(t, payload.Display.Fields, 2)
}

func TestNewPamAuthPayload_SSHContext(t *testing.T) {
	authSock := true
	authCtx := &AuthContext{
		LocalUsername:      "admin",
		PAMService:         "sshd",
		Hostname:           "server1",
		SSHClient:          "192.168.1.100 54321 22",
		SSHConnection:      "192.168.1.100 54321 10.0.0.1 22",
		SSHAuthSockPresent: &authSock,
	}

	payload := NewPamAuthPayload(authCtx, "admin@example.com")

	require.NotNil(t, payload.SshClient)
	assert.Equal(t, "192.168.1.100 54321 22", *payload.SshClient)
	require.NotNil(t, payload.SshConnection)
	assert.Equal(t, "192.168.1.100 54321 10.0.0.1 22", *payload.SshConnection)
	require.NotNil(t, payload.SshAuthSockPresent)
	assert.True(t, *payload.SshAuthSockPresent)
}

func TestPtrIfNotEmpty(t *testing.T) {
	// Non-empty string returns pointer
	result := ptrIfNotEmpty("hello")
	require.NotNil(t, result)
	assert.Equal(t, "hello", *result)

	// Empty string returns nil
	result = ptrIfNotEmpty("")
	assert.Nil(t, result)
}

func TestRelayResponseStatus_Responded(t *testing.T) {
	status := RelayResponseStatus{
		ID:                   "req-123",
		Status:               "responded",
		EncryptedResponse:    []byte("ciphertext"),
		ApproverEphemeralKey: []byte("ephemeral-key"),
		ResponseNonce:        []byte("nonce"),
	}

	assert.Equal(t, "req-123", status.ID)
	assert.Equal(t, "responded", status.Status)
	assert.NotEmpty(t, status.EncryptedResponse)
	assert.NotEmpty(t, status.ApproverEphemeralKey)
	assert.NotEmpty(t, status.ResponseNonce)
}

func TestRelayResponseStatus_Pending(t *testing.T) {
	status := RelayResponseStatus{
		ID:     "req-456",
		Status: "pending",
	}

	assert.Equal(t, "pending", status.Status)
	assert.Nil(t, status.EncryptedResponse)
}

func TestNewPamAuthPayload_WithOSVersion(t *testing.T) {
	authCtx := &AuthContext{
		LocalUsername: "admin",
		PAMService:    "sshd",
		Hostname:      "server1",
		OSVersion:     "Ubuntu 22.04",
	}

	payload := NewPamAuthPayload(authCtx, "admin@example.com")
	require.NotNil(t, payload.OsVersion)
	assert.Equal(t, "Ubuntu 22.04", *payload.OsVersion)
}

func TestNewPamAuthPayload_WithTTY(t *testing.T) {
	authCtx := &AuthContext{
		LocalUsername: "admin",
		PAMService:    "login",
		Hostname:      "server1",
		TTY:           "/dev/pts/3",
	}

	payload := NewPamAuthPayload(authCtx, "admin@example.com")
	require.NotNil(t, payload.Tty)
	assert.Equal(t, "/dev/pts/3", *payload.Tty)
}
