//go:build linux

package sysinfo

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// GetProcessInfo returns information about the current process and its ancestry.
// On Linux, it reads from the /proc filesystem directly.
func GetProcessInfo() ProcessInfo {
	var chain []ProcessEntry
	var command string

	pid := os.Getpid()
	firstPID := pid

	// Walk up the process tree until we hit init (PID 1) or can't continue
	for pid > 0 {
		cmdLine := getCommandLineForPid(pid)
		if cmdLine == "" {
			break
		}

		// Get UID and convert to username
		uid := getProcessUID(pid)
		username := LookupUsername(uid)

		entry := ProcessEntry{
			PID:      pid,
			Username: username,
			Command:  cmdLine,
		}
		chain = append(chain, entry)

		// Save the first process's command
		if pid == firstPID {
			command = cmdLine
		}

		// Stop at init/systemd (PID 1)
		if pid == 1 {
			break
		}

		// Get parent PID
		ppid := getParentPid(pid)
		if ppid <= 0 {
			break
		}
		pid = ppid
	}

	return ProcessInfo{
		Command:      command,
		ProcessChain: chain,
		Hostname:     GetHostname(),
		LocalIP:      GetLocalIP(),
		Username:     GetCurrentUsername(),
	}
}

// getCommandLineForPid returns the command line for a specific PID.
func getCommandLineForPid(pid int) string {
	path := fmt.Sprintf("/proc/%d/cmdline", pid)
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}

	// /proc/[pid]/cmdline has null-separated arguments
	// Replace null bytes with spaces, trim trailing null
	data = bytes.TrimRight(data, "\x00")
	return string(bytes.ReplaceAll(data, []byte{0}, []byte{' '}))
}

// getProcessUID returns the UID for a given process.
// Returns -1 on error.
func getProcessUID(pid int) int {
	// Read /proc/[pid]/status which contains:
	// Uid:	1000	1000	1000	1000
	path := fmt.Sprintf("/proc/%d/status", pid)
	data, err := os.ReadFile(path)
	if err != nil {
		return -1
	}

	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				uid, err := strconv.Atoi(fields[1])
				if err != nil {
					return -1
				}
				return uid
			}
		}
	}
	return -1
}

// getParentPid returns the parent PID for a given process.
// Returns -1 on error.
func getParentPid(pid int) int {
	// Read /proc/[pid]/stat which contains:
	// pid (comm) state ppid ...
	// The ppid is field 4 (1-indexed)
	path := fmt.Sprintf("/proc/%d/stat", pid)
	data, err := os.ReadFile(path)
	if err != nil {
		return -1
	}

	content := string(data)

	// The comm field is in parentheses and can contain spaces/special chars
	// Find the last ')' to skip past comm
	lastParen := strings.LastIndex(content, ")")
	if lastParen == -1 || lastParen+2 >= len(content) {
		return -1
	}

	// After the comm field: " state ppid ..."
	rest := content[lastParen+2:]
	fields := strings.Fields(rest)
	if len(fields) < 2 {
		return -1
	}

	// fields[0] is state, fields[1] is ppid
	ppid, err := strconv.Atoi(fields[1])
	if err != nil {
		return -1
	}

	return ppid
}
