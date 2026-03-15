// Package config provides configuration and constants for the CLI.
package config

import "time"

// Timeout constants for signing and approval operations.
const (
	// DefaultSigningTimeout is used for GPG signing and hook approvals
	// where the user has more time to respond.
	DefaultSigningTimeout = 120 * time.Second

	// DefaultSSHTimeout is used for SSH operations which may need
	// faster response for interactive authentication flows.
	DefaultSSHTimeout = 60 * time.Second
)
