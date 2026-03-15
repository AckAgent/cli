//go:build darwin

package main

/*
#include <sys/sysctl.h>
#include <sys/proc_info.h>
#include <libproc.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <sys/types.h>

// Debug flag - set via environment or externally
static int cmdline_debug = 0;

void set_cmdline_debug(int enabled) {
    cmdline_debug = enabled;
}

// Get parent PID for a given process
// Returns -1 on error
pid_t get_parent_pid(pid_t pid) {
    struct kinfo_proc info;
    size_t size = sizeof(info);
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};

    if (sysctl(mib, 4, &info, &size, NULL, 0) < 0) {
        if (cmdline_debug) fprintf(stderr, "[cmdline] get_parent_pid(%d) failed: errno=%d\n", pid, errno);
        return -1;
    }

    if (size == 0) {
        if (cmdline_debug) fprintf(stderr, "[cmdline] get_parent_pid(%d): process not found\n", pid);
        return -1;
    }

    pid_t ppid = info.kp_eproc.e_ppid;
    if (cmdline_debug) fprintf(stderr, "[cmdline] get_parent_pid(%d) = %d\n", pid, ppid);
    return ppid;
}

// Get UID for a given process
// Returns (uid_t)-1 on error
uid_t get_process_uid(pid_t pid) {
    struct kinfo_proc info;
    size_t size = sizeof(info);
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};

    if (sysctl(mib, 4, &info, &size, NULL, 0) < 0) {
        if (cmdline_debug) fprintf(stderr, "[cmdline] get_process_uid(%d) failed: errno=%d\n", pid, errno);
        return (uid_t)-1;
    }

    if (size == 0) {
        if (cmdline_debug) fprintf(stderr, "[cmdline] get_process_uid(%d): process not found\n", pid);
        return (uid_t)-1;
    }

    uid_t uid = info.kp_eproc.e_ucred.cr_uid;
    if (cmdline_debug) fprintf(stderr, "[cmdline] get_process_uid(%d) = %d\n", pid, uid);
    return uid;
}

// Get command line arguments for a given PID using sysctl
// Returns a null-terminated string with arguments separated by spaces
// Caller must free the returned pointer
char* get_process_cmdline_for_pid(pid_t pid) {
    int mib[3] = {CTL_KERN, KERN_PROCARGS2, pid};
    size_t size = 0;

    if (cmdline_debug) fprintf(stderr, "[cmdline] getting args for pid %d\n", pid);

    // Get size needed
    if (sysctl(mib, 3, NULL, &size, NULL, 0) < 0) {
        if (cmdline_debug) fprintf(stderr, "[cmdline] sysctl size query failed for pid %d: errno=%d\n", pid, errno);
        return NULL;
    }
    if (cmdline_debug) fprintf(stderr, "[cmdline] sysctl reports size=%zu for pid %d\n", size, pid);

    char* buf = (char*)malloc(size);
    if (buf == NULL) {
        return NULL;
    }

    // Get actual data
    if (sysctl(mib, 3, buf, &size, NULL, 0) < 0) {
        if (cmdline_debug) fprintf(stderr, "[cmdline] sysctl data query failed for pid %d: errno=%d\n", pid, errno);
        free(buf);
        return NULL;
    }

    // KERN_PROCARGS2 format:
    // - 4 bytes: argc (number of arguments)
    // - executable path (null-terminated)
    // - padding nulls
    // - arg0 (null-terminated)
    // - arg1 (null-terminated)
    // - ...

    if (size < sizeof(int)) {
        free(buf);
        return NULL;
    }

    int argc = *(int*)buf;
    char* ptr = buf + sizeof(int);
    char* end = buf + size;

    // Skip executable path
    while (ptr < end && *ptr != '\0') ptr++;
    // Skip nulls after executable path
    while (ptr < end && *ptr == '\0') ptr++;

    // Calculate total length needed for result
    size_t total_len = 0;
    char* scan = ptr;
    int count = 0;
    while (scan < end && count < argc) {
        size_t arg_len = strlen(scan);
        if (arg_len == 0) break;
        total_len += arg_len + 1;  // +1 for space or null terminator
        scan += arg_len + 1;
        count++;
    }

    if (total_len == 0) {
        free(buf);
        return NULL;
    }

    char* result = (char*)malloc(total_len);
    if (result == NULL) {
        free(buf);
        return NULL;
    }

    // Build result string with spaces between args
    char* dst = result;
    count = 0;
    while (ptr < end && count < argc) {
        size_t arg_len = strlen(ptr);
        if (arg_len == 0) break;

        if (count > 0) {
            *dst++ = ' ';
        }
        memcpy(dst, ptr, arg_len);
        dst += arg_len;

        ptr += arg_len + 1;
        count++;
    }
    *dst = '\0';

    free(buf);
    return result;
}

// Find all PIDs that have a given file path open
// Returns number of bytes written to buffer, -1 on error
int find_pids_with_path(const char* path, pid_t* buffer, int buffer_size) {
    if (cmdline_debug) fprintf(stderr, "[cmdline] find_pids_with_path: %s\n", path);
    int result = proc_listpidspath(PROC_ALL_PIDS, 0, path, 0, buffer, buffer_size);
    if (cmdline_debug) fprintf(stderr, "[cmdline] find_pids_with_path result: %d\n", result);
    return result;
}
*/
import "C"

import (
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/ackagent/cli/internal/shared/log"
	"github.com/ackagent/cli/internal/shared/sysinfo"
)

// getProcessInfo walks the process tree to find the actual SSH command.
// It starts from the current process (ssh-sk-helper) and walks up to init/launchd.
// If ssh-agent is in the chain, it also finds processes connected to the agent socket.
func getProcessInfo() ProcessInfo {
	// Enable C debug logging if Go debug is enabled
	if log.IsDebug() {
		C.set_cmdline_debug(1)
	}

	var chain []sysinfo.ProcessEntry
	var sshCommand string
	var agentPID C.pid_t // Track ssh-agent if we find it

	pid := C.pid_t(os.Getpid())

	// Walk up the process tree until we hit init/launchd (PID 1) or can't continue
	for pid > 1 {
		cstr := C.get_process_cmdline_for_pid(pid)
		if cstr == nil {
			logDebug("get_process_cmdline_for_pid(%d) returned nil", pid)
			break
		}

		cmdLine := C.GoString(cstr)
		C.free(unsafe.Pointer(cstr))

		// Get UID and convert to username
		uid := C.get_process_uid(pid)
		username := sysinfo.LookupUsername(int(uid))

		logDebug("pid %d uid %d (%s) cmdline: %s", pid, uid, username, cmdLine)

		entry := sysinfo.ProcessEntry{
			PID:      int(pid),
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
		ppid := C.get_parent_pid(pid)
		if ppid <= 1 {
			// Try to add init/launchd (PID 1) if accessible
			if ppid == 1 {
				initStr := C.get_process_cmdline_for_pid(1)
				if initStr != nil {
					initCmd := C.GoString(initStr)
					C.free(unsafe.Pointer(initStr))
					initUID := C.get_process_uid(1)
					chain = append(chain, sysinfo.ProcessEntry{
						PID:      1,
						Username: sysinfo.LookupUsername(int(initUID)),
						Command:  initCmd,
					})
					logDebug("added init/launchd: %s", initCmd)
				}
			}
			break
		}
		pid = ppid
	}

	// If we found ssh-agent, try to find connected clients
	var agentClients []sysinfo.ProcessEntry
	if agentPID > 0 {
		agentClients = findAgentClients(int(agentPID))
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

// getCommandLineForPidGo is a Go wrapper for the C function
func getCommandLineForPidGo(pid int) string {
	cstr := C.get_process_cmdline_for_pid(C.pid_t(pid))
	if cstr == nil {
		return ""
	}
	result := C.GoString(cstr)
	C.free(unsafe.Pointer(cstr))
	return result
}

// findAgentClients finds processes connected to the ssh-agent socket
func findAgentClients(agentPID int) []sysinfo.ProcessEntry {
	socketPath := getAgentSocketPath()
	if socketPath == "" {
		return nil
	}

	// Convert path to C string
	cPath := C.CString(socketPath)
	defer C.free(unsafe.Pointer(cPath))

	// Buffer for PIDs (up to 64 processes)
	var pids [64]C.pid_t
	bufSize := C.int(len(pids) * int(unsafe.Sizeof(pids[0])))

	result := C.find_pids_with_path(cPath, &pids[0], bufSize)
	if result <= 0 {
		logDebug("no processes found with socket open (result=%d)", result)
		return nil
	}

	// proc_listpidspath returns number of bytes, divide by sizeof(pid_t) to get count
	count := int(result) / int(unsafe.Sizeof(pids[0]))
	logDebug("found %d processes with socket open", count)

	var clients []sysinfo.ProcessEntry
	myPID := os.Getpid()

	for i := 0; i < count && i < len(pids); i++ {
		pid := int(pids[i])

		// Skip ourselves, ssh-agent, and invalid PIDs
		if pid == myPID || pid == agentPID || pid <= 1 {
			continue
		}

		cmdLine := getCommandLineForPidGo(pid)
		if cmdLine == "" {
			continue
		}

		// Skip ssh-agent and ssh-sk-helper
		if isSSHAgent(cmdLine) || strings.Contains(cmdLine, "ssh-sk-helper") {
			continue
		}

		uid := int(C.get_process_uid(C.pid_t(pid)))
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
