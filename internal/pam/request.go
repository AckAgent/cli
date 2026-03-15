package pam

import (
	"fmt"

	protocol "github.com/ackagent/api/go/protocol"
	"github.com/ackagent/cli/internal/shared/util"
)

// NewPamAuthPayload creates a protocol.PamAuthPayload from an AuthContext.
func NewPamAuthPayload(ctx *AuthContext, ackAgentUser string) *protocol.PamAuthPayload {
	// Build display fields for PAM-specific context
	personIcon := "person.fill"
	networkIcon := "network"
	terminalIcon := "terminal"

	fields := []protocol.DisplayField{
		{
			Label: "Local User",
			Value: ctx.LocalUsername,
			Icon:  &personIcon,
		},
		{
			Label:     "Service",
			Value:     ctx.PAMService,
			Monospace: util.Ptr(true),
		},
	}

	if ctx.RemoteHost != "" {
		fields = append(fields, protocol.DisplayField{
			Label:     "Remote Host",
			Value:     ctx.RemoteHost,
			Icon:      &networkIcon,
			Monospace: util.Ptr(true),
		})
	}

	if ctx.SudoCommand != "" {
		fields = append(fields, protocol.DisplayField{
			Label:     "Sudo Command",
			Value:     ctx.SudoCommand,
			Icon:      &terminalIcon,
			Monospace: util.Ptr(true),
		})
	}

	icon := "server.rack"
	subtitle := fmt.Sprintf("%s via %s", ctx.LocalUsername, ctx.PAMService)

	return &protocol.PamAuthPayload{
		Type:               protocol.PamAuth,
		LocalUsername:      ctx.LocalUsername,
		AckagentUser:       ackAgentUser,
		PamService:         ctx.PAMService,
		RemoteHost:         ptrIfNotEmpty(ctx.RemoteHost),
		Tty:                ptrIfNotEmpty(ctx.TTY),
		OsVersion:          ptrIfNotEmpty(ctx.OSVersion),
		SshClient:          ptrIfNotEmpty(ctx.SSHClient),
		SshConnection:      ptrIfNotEmpty(ctx.SSHConnection),
		SshOriginalCommand: ptrIfNotEmpty(ctx.SSHOriginalCommand),
		SshAuthSockPresent: ctx.SSHAuthSockPresent,
		SudoUser:           ptrIfNotEmpty(ctx.SudoUser),
		SudoCommand:        ptrIfNotEmpty(ctx.SudoCommand),
		SourceInfo:         ctx.SourceInfo,
		Timestamp:          ctx.Timestamp,
		Display: &protocol.GenericDisplaySchema{
			Title:    fmt.Sprintf("Login to %s", ctx.Hostname),
			Subtitle: &subtitle,
			Icon:     &icon,
			Fields:   fields,
		},
	}
}

// ptrIfNotEmpty returns a pointer to s if s is not empty, otherwise nil.
func ptrIfNotEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// RelayResponseStatus holds the raw encrypted response from the relay.
// The relay never reveals approval/rejection — that's inside the E2E encrypted payload.
// Attestation is now anonymous (BBS+ proof) inside the encrypted response blob,
// not attached as identified-mode metadata on the relay response.
type RelayResponseStatus struct {
	ID                   string
	Status               string // "pending", "responded", "expired"
	EncryptedResponse    []byte
	ApproverEphemeralKey []byte
	ResponseNonce        []byte
}
