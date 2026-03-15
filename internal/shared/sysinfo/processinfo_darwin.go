//go:build darwin

package sysinfo

/*
#include <sys/sysctl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

// Get parent PID for a given process
// Returns -1 on error
pid_t sysinfo_get_parent_pid(pid_t pid) {
    struct kinfo_proc info;
    size_t size = sizeof(info);
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};

    if (sysctl(mib, 4, &info, &size, NULL, 0) < 0) {
        return -1;
    }

    if (size == 0) {
        return -1;
    }

    return info.kp_eproc.e_ppid;
}

// Get UID for a given process
// Returns (uid_t)-1 on error
uid_t sysinfo_get_process_uid(pid_t pid) {
    struct kinfo_proc info;
    size_t size = sizeof(info);
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};

    if (sysctl(mib, 4, &info, &size, NULL, 0) < 0) {
        return (uid_t)-1;
    }

    if (size == 0) {
        return (uid_t)-1;
    }

    return info.kp_eproc.e_ucred.cr_uid;
}

// Get command line arguments for a given PID using sysctl
// Returns a null-terminated string with arguments separated by spaces
// Caller must free the returned pointer
char* sysinfo_get_process_cmdline_for_pid(pid_t pid) {
    int mib[3] = {CTL_KERN, KERN_PROCARGS2, pid};
    size_t size = 0;

    // Get size needed
    if (sysctl(mib, 3, NULL, &size, NULL, 0) < 0) {
        return NULL;
    }

    char* buf = (char*)malloc(size);
    if (buf == NULL) {
        return NULL;
    }

    // Get actual data
    if (sysctl(mib, 3, buf, &size, NULL, 0) < 0) {
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
*/
import "C"

import (
	"os"
	"unsafe"
)

// GetProcessInfo returns information about the current process and its ancestry.
// On macOS, it uses sysctl to query process information.
func GetProcessInfo() ProcessInfo {
	var chain []ProcessEntry
	var command string

	pid := C.pid_t(os.Getpid())
	firstPID := pid

	// Walk up the process tree until we hit launchd (PID 1) or can't continue
	for pid > 0 {
		cstr := C.sysinfo_get_process_cmdline_for_pid(pid)
		if cstr == nil {
			break
		}

		cmdLine := C.GoString(cstr)
		C.free(unsafe.Pointer(cstr))

		// Get UID and convert to username
		uid := C.sysinfo_get_process_uid(pid)
		username := LookupUsername(int(uid))

		entry := ProcessEntry{
			PID:      int(pid),
			Username: username,
			Command:  cmdLine,
		}
		chain = append(chain, entry)

		// Save the first process's command
		if pid == firstPID {
			command = cmdLine
		}

		// Stop at launchd (PID 1)
		if pid == 1 {
			break
		}

		// Get parent PID
		ppid := C.sysinfo_get_parent_pid(pid)
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
