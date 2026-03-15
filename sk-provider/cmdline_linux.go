//go:build linux

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ackagent/cli/internal/shared/sysinfo"
)

// getProcessInfo walks the process tree to find the actual SSH command.
// It starts from the current process (ssh-sk-helper) and walks up to init.
// If ssh-agent is in the chain, it also finds processes connected to the agent socket.
func getProcessInfo() ProcessInfo {
	var chain []sysinfo.ProcessEntry
	var sshCommand string
	var agentPID int // Track ssh-agent if we find it

	pid := os.Getpid()

	// Walk up the process tree until we hit init (PID 1) or can't continue
	for pid > 1 {
		cmdLine := getCommandLineForPid(pid)
		if cmdLine == "" {
			logDebug("getCommandLineForPid(%d) returned empty", pid)
			break
		}

		// Get UID and convert to username
		uid := getProcessUID(pid)
		username := sysinfo.LookupUsername(uid)

		logDebug("pid %d uid %d (%s) cmdline: %s", pid, uid, username, cmdLine)

		entry := sysinfo.ProcessEntry{
			PID:      pid,
			Username: username,
			Command:  cmdLine,
		}
		chain = append(chain, entry)

		// Track SSH command if found (but don't stop - continue to get full chain)
		if isSSHCommand(cmdLine) {
			sshCommand = cmdLine
			logDebug("found ssh command at pid %d: %s", pid, cmdLine)
		}

		// Track ssh-agent if found
		if isSSHAgent(cmdLine) {
			agentPID = pid
			logDebug("found ssh-agent at pid %d", pid)
		}

		// Get parent PID
		ppid := getParentPid(pid)
		if ppid <= 1 {
			// Try to add init (PID 1) if accessible
			if ppid == 1 {
				initCmd := getCommandLineForPid(1)
				if initCmd != "" {
					initUID := getProcessUID(1)
					chain = append(chain, sysinfo.ProcessEntry{
						PID:      1,
						Username: sysinfo.LookupUsername(initUID),
						Command:  initCmd,
					})
					logDebug("added init: %s", initCmd)
				}
			}
			break
		}
		pid = ppid
	}

	// If we found ssh-agent, try to find connected clients
	var agentClients []sysinfo.ProcessEntry
	if agentPID > 0 {
		agentClients = findAgentClients(agentPID)
		// If we didn't find a direct SSH command but found agent clients,
		// use the first client as the command
		if sshCommand == "" && len(agentClients) > 0 {
			sshCommand = agentClients[0].Command
			logDebug("using agent client as ssh command: %s", sshCommand)
		}
	}

	// Fallback: if we still didn't find an SSH command, use parent of ssh-sk-helper
	if sshCommand == "" && len(chain) > 1 {
		sshCommand = chain[1].Command
		logDebug("no ssh command found, using parent: %s", sshCommand)
	} else if sshCommand == "" && len(chain) > 0 {
		sshCommand = chain[0].Command
		logDebug("no parent found, using current: %s", sshCommand)
	}

	return ProcessInfo{
		ProcessInfo: sysinfo.ProcessInfo{
			Command:      sshCommand,
			ProcessChain: chain,
			Hostname:     sysinfo.GetHostname(),
			LocalIP:      sysinfo.GetLocalIP(),
			Username:     sysinfo.GetCurrentUsername(),
		},
		AgentClients: agentClients,
	}
}

// getCommandLineForPid returns the command line for a specific PID.
func getCommandLineForPid(pid int) string {
	path := fmt.Sprintf("/proc/%d/cmdline", pid)
	data, err := os.ReadFile(path)
	if err != nil {
		logDebug("failed to read %s: %v", path, err)
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
		logDebug("failed to read %s: %v", path, err)
		return -1
	}

	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				uid, err := strconv.Atoi(fields[1])
				if err != nil {
					logDebug("failed to parse uid: %v", err)
					return -1
				}
				logDebug("getProcessUID(%d) = %d", pid, uid)
				return uid
			}
		}
	}
	logDebug("getProcessUID(%d): uid not found", pid)
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
		logDebug("failed to read %s: %v", path, err)
		return -1
	}

	content := string(data)

	// The comm field is in parentheses and can contain spaces/special chars
	// Find the last ')' to skip past comm
	lastParen := strings.LastIndex(content, ")")
	if lastParen == -1 || lastParen+2 >= len(content) {
		logDebug("failed to parse stat for pid %d", pid)
		return -1
	}

	// After the comm field: " state ppid ..."
	rest := content[lastParen+2:]
	fields := strings.Fields(rest)
	if len(fields) < 2 {
		logDebug("not enough fields in stat for pid %d", pid)
		return -1
	}

	// fields[0] is state, fields[1] is ppid
	ppid, err := strconv.Atoi(fields[1])
	if err != nil {
		logDebug("failed to parse ppid for pid %d: %v", pid, err)
		return -1
	}

	logDebug("getParentPid(%d) = %d", pid, ppid)
	return ppid
}

// isSSHCommand checks if a command line looks like an SSH client command
func isSSHCommand(cmdLine string) bool {
	if cmdLine == "" {
		return false
	}

	// Get the base name of the first argument (the executable)
	parts := strings.Fields(cmdLine)
	if len(parts) == 0 {
		return false
	}

	baseName := filepath.Base(parts[0])

	// Match 'ssh' but not 'ssh-sk-helper', 'ssh-agent', 'ssh-add', 'sshd', etc.
	if baseName == "ssh" {
		return true
	}

	return false
}

// isSSHAgent checks if a command line looks like ssh-agent
func isSSHAgent(cmdLine string) bool {
	if cmdLine == "" {
		return false
	}
	parts := strings.Fields(cmdLine)
	if len(parts) == 0 {
		return false
	}
	baseName := filepath.Base(parts[0])
	return baseName == "ssh-agent"
}

// getAgentSocketPath returns the SSH_AUTH_SOCK path from the environment
func getAgentSocketPath() string {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		logDebug("SSH_AUTH_SOCK environment variable not set")
		return ""
	}
	logDebug("found SSH_AUTH_SOCK=%s", sock)
	return sock
}

// findSocketInode finds the inode number for a Unix socket path
func findSocketInode(socketPath string) uint64 {
	// Read /proc/net/unix and find the inode for this path
	data, err := os.ReadFile("/proc/net/unix")
	if err != nil {
		logDebug("failed to read /proc/net/unix: %v", err)
		return 0
	}

	for _, line := range strings.Split(string(data), "\n") {
		// Format: Num RefCount Protocol Flags Type St Inode Path
		// Path is optional and at the end
		if strings.HasSuffix(line, socketPath) {
			fields := strings.Fields(line)
			if len(fields) >= 7 {
				inode, err := strconv.ParseUint(fields[6], 10, 64)
				if err == nil {
					logDebug("found socket inode %d for path %s", inode, socketPath)
					return inode
				}
			}
		}
	}
	logDebug("socket inode not found for path %s", socketPath)
	return 0
}

// findPidsWithInode finds all process IDs that have a file descriptor pointing to the given socket inode
func findPidsWithInode(inode uint64) []int {
	var pids []int
	inodeStr := fmt.Sprintf("socket:[%d]", inode)

	entries, err := os.ReadDir("/proc")
	if err != nil {
		logDebug("failed to read /proc: %v", err)
		return nil
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		fdPath := fmt.Sprintf("/proc/%d/fd", pid)
		fds, err := os.ReadDir(fdPath)
		if err != nil {
			continue // Can't read this process's fds (permission denied, process exited, etc.)
		}

		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdPath, fd.Name()))
			if err == nil && link == inodeStr {
				pids = append(pids, pid)
				logDebug("found process %d with socket inode %d", pid, inode)
				break
			}
		}
	}
	return pids
}

// findAgentClients finds processes connected to the ssh-agent socket
func findAgentClients(agentPID int) []sysinfo.ProcessEntry {
	socketPath := getAgentSocketPath()
	if socketPath == "" {
		return nil
	}

	// Find socket inode from /proc/net/unix
	inode := findSocketInode(socketPath)
	if inode == 0 {
		return nil
	}

	// Scan /proc/*/fd/ to find processes with this inode
	pids := findPidsWithInode(inode)

	var clients []sysinfo.ProcessEntry
	myPID := os.Getpid()

	for _, pid := range pids {
		// Skip ourselves, ssh-agent, and invalid PIDs
		if pid == myPID || pid == agentPID || pid <= 1 {
			continue
		}

		cmdLine := getCommandLineForPid(pid)
		if cmdLine == "" {
			continue
		}

		// Skip ssh-agent and ssh-sk-helper
		if isSSHAgent(cmdLine) || strings.Contains(cmdLine, "ssh-sk-helper") {
			continue
		}

		uid := getProcessUID(pid)
		entry := sysinfo.ProcessEntry{
			PID:      pid,
			Username: sysinfo.LookupUsername(uid),
			Command:  cmdLine,
		}
		clients = append(clients, entry)
		logDebug("found agent client: pid=%d cmd=%s", pid, cmdLine)
	}

	return clients
}
