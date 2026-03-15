package sysinfo

import (
	"os"
	"testing"
)

func TestGetProcessInfo(t *testing.T) {
	info := GetProcessInfo()

	// Should have at least the current process
	if len(info.ProcessChain) == 0 {
		t.Error("ProcessChain should not be empty")
	}

	// First entry should be our process
	if len(info.ProcessChain) > 0 {
		first := info.ProcessChain[0]
		if first.PID != os.Getpid() {
			t.Errorf("First PID should be %d, got %d", os.Getpid(), first.PID)
		}
		if first.Command == "" {
			t.Error("First process should have a command")
		}
		if first.Username == "" {
			t.Error("First process should have a username")
		}
	}

	// Command should match first process
	if info.Command == "" {
		t.Error("Command should not be empty")
	}

	// Username should be set
	if info.Username == "" {
		t.Error("Username should not be empty")
	}

	// Hostname should be set (unless running in unusual environment)
	if info.Hostname == "" {
		t.Log("Warning: Hostname is empty")
	}
}

func TestGetCurrentUsername(t *testing.T) {
	username := GetCurrentUsername()
	if username == "" {
		t.Error("GetCurrentUsername should return a non-empty string")
	}
}

func TestGetHostname(t *testing.T) {
	hostname := GetHostname()
	// Hostname should generally be available
	if hostname == "" {
		t.Log("Warning: Hostname is empty - this may be expected in some environments")
	}
}

func TestGetLocalIP(t *testing.T) {
	ip := GetLocalIP()
	// IP might be empty if no network interfaces
	if ip == "" {
		t.Log("Warning: LocalIP is empty - this may be expected in some environments")
	}
}
