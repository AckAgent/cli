// Package sysinfo provides utilities for collecting system information
// such as hostname, local IP addresses, and process tree information.
package sysinfo

import (
	"os"
	"os/user"
	"strconv"
)

// ProcessEntry contains detailed information about a single process in the chain.
type ProcessEntry struct {
	PID      int    `json:"pid"`
	Username string `json:"username"`
	Command  string `json:"command"`
}

// ProcessInfo contains information about the current process and its ancestry.
type ProcessInfo struct {
	Command      string         `json:"command"`      // Command line of current process
	ProcessChain []ProcessEntry `json:"processChain"` // Full chain from current process up to init
	Hostname     string         `json:"hostname"`     // Machine hostname
	LocalIP      string         `json:"localIp"`      // Local/private IP address
	Username     string         `json:"username"`     // Current user running the process
}

// GetCurrentUsername returns the username of the current process owner.
func GetCurrentUsername() string {
	u, err := user.Current()
	if err != nil {
		// Fallback to looking up by UID
		uid := os.Getuid()
		if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
			return u.Username
		}
		return ""
	}
	return u.Username
}

// LookupUsername converts a UID to a username string.
// Returns "uid:N" format if the username cannot be resolved.
func LookupUsername(uid int) string {
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return "uid:" + strconv.Itoa(uid)
	}
	return u.Username
}
