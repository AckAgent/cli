package pam

import (
	"os"
	"os/exec"
	"strings"
	"time"

	protocol "github.com/ackagent/api/go/protocol"
	"github.com/ackagent/cli/internal/shared/sysinfo"
)

// AuthContext contains information about the authentication attempt.
// This is gathered from PAM environment and system state.
type AuthContext struct {
	// LocalUsername is the local Unix username being authenticated.
	LocalUsername string `json:"localUsername"`

	// PAMService is the PAM service name (e.g., "sshd", "sudo", "login").
	PAMService string `json:"pamService"`

	// TTY is the terminal device (if available).
	TTY string `json:"tty,omitempty"`

	// RemoteHost is the remote host IP (from PAM_RHOST).
	RemoteHost string `json:"remoteHost,omitempty"`

	// Hostname is the hostname of the PAM host.
	Hostname string `json:"hostname"`

	// OSVersion is the OS version information.
	OSVersion string `json:"osVersion,omitempty"`

	// SSHClient is the SSH client info (from SSH_CLIENT env var).
	SSHClient string `json:"sshClient,omitempty"`

	// SSHConnection is the SSH connection info (from SSH_CONNECTION env var).
	SSHConnection string `json:"sshConnection,omitempty"`

	// SSHOriginalCommand is the SSH original command (from SSH_ORIGINAL_COMMAND).
	SSHOriginalCommand string `json:"sshOriginalCommand,omitempty"`

	// SSHAuthSockPresent indicates whether SSH auth socket is present.
	SSHAuthSockPresent *bool `json:"sshAuthSockPresent,omitempty"`

	// SudoUser is the sudo originating user (from SUDO_USER).
	SudoUser string `json:"sudoUser,omitempty"`

	// SudoCommand is the sudo command (from SUDO_COMMAND).
	SudoCommand string `json:"sudoCommand,omitempty"`

	// SourceInfo contains system and process ancestry information.
	SourceInfo *protocol.SourceInfo `json:"sourceInfo,omitempty"`

	// Timestamp is the request timestamp (Unix epoch seconds).
	Timestamp int64 `json:"timestamp"`
}

// PAMEnv represents PAM environment variables passed to the module.
type PAMEnv struct {
	TTY        string // PAM_TTY
	RemoteHost string // PAM_RHOST
	// Add more PAM items as needed
}

// NewAuthContext creates a new AuthContext with basic information.
func NewAuthContext(username, service string) *AuthContext {
	return &AuthContext{
		LocalUsername: username,
		PAMService:    service,
		Hostname:      sysinfo.GetHostname(),
		OSVersion:     getOSVersion(),
		Timestamp:     time.Now().Unix(),
	}
}

// GatherContext gathers full context from PAM environment and system state.
func GatherContext(username, service string, pamEnv *PAMEnv) *AuthContext {
	ctx := NewAuthContext(username, service)

	// Get TTY from PAM or environment
	if pamEnv != nil && pamEnv.TTY != "" {
		ctx.TTY = pamEnv.TTY
	} else if tty := os.Getenv("TTY"); tty != "" {
		ctx.TTY = tty
	}

	// Get remote host from PAM
	if pamEnv != nil && pamEnv.RemoteHost != "" {
		ctx.RemoteHost = pamEnv.RemoteHost
	}

	// Gather SSH-related environment variables
	ctx.SSHClient = os.Getenv("SSH_CLIENT")
	ctx.SSHConnection = os.Getenv("SSH_CONNECTION")
	ctx.SSHOriginalCommand = os.Getenv("SSH_ORIGINAL_COMMAND")

	_, sshAuthSockExists := os.LookupEnv("SSH_AUTH_SOCK")
	ctx.SSHAuthSockPresent = &sshAuthSockExists

	// Gather sudo-related environment variables
	ctx.SudoUser = os.Getenv("SUDO_USER")
	ctx.SudoCommand = os.Getenv("SUDO_COMMAND")

	// Build source info with process chain
	ctx.SourceInfo = buildSourceInfo()

	return ctx
}

// getOSVersion returns OS version information.
func getOSVersion() string {
	// Try /etc/os-release first (most Linux distributions)
	data, err := os.ReadFile("/etc/os-release")
	if err == nil {
		for line := range strings.SplitSeq(string(data), "\n") {
			if value, found := strings.CutPrefix(line, "PRETTY_NAME="); found {
				return strings.Trim(value, "\"")
			}
		}
	}

	// Fallback to uname
	out, err := exec.Command("uname", "-sr").Output()
	if err == nil {
		return strings.TrimSpace(string(out))
	}

	return ""
}

// buildSourceInfo returns source information including process ancestry.
func buildSourceInfo() *protocol.SourceInfo {
	return sysinfo.GetProcessInfo().ToSourceInfo()
}
