package sysinfo

import (
	"strconv"
	"testing"
)

func TestLookupUsername(t *testing.T) {
	// Current user should resolve to a username
	username := LookupUsername(0) // root
	if username == "" {
		t.Error("LookupUsername(0) returned empty string")
	}

	// Invalid UID should return "uid:N" format
	invalidUID := 999999
	result := LookupUsername(invalidUID)
	expected := "uid:" + strconv.Itoa(invalidUID)
	if result != expected {
		t.Errorf("LookupUsername(%d) = %q, want %q", invalidUID, result, expected)
	}
}

func TestToSourceInfo(t *testing.T) {
	// Test with populated ProcessInfo
	info := ProcessInfo{
		Command:  "test-command",
		Hostname: "test-host",
		LocalIP:  "192.168.1.1",
		Username: "testuser",
		ProcessChain: []ProcessEntry{
			{PID: 1234, Username: "testuser", Command: "test-command"},
			{PID: 1, Username: "root", Command: "init"},
		},
	}

	si := info.ToSourceInfo()
	if si == nil {
		t.Fatal("ToSourceInfo() returned nil")
	}

	if si.Hostname == nil || *si.Hostname != "test-host" {
		t.Errorf("Hostname = %v, want test-host", si.Hostname)
	}
	if si.LocalIp == nil || *si.LocalIp != "192.168.1.1" {
		t.Errorf("LocalIp = %v, want 192.168.1.1", si.LocalIp)
	}
	if si.Username == nil || *si.Username != "testuser" {
		t.Errorf("Username = %v, want testuser", si.Username)
	}
	if si.Command == nil || *si.Command != "test-command" {
		t.Errorf("Command = %v, want test-command", si.Command)
	}
	if si.ProcessChain == nil {
		t.Fatal("ProcessChain is nil")
	}
	chain := *si.ProcessChain
	if len(chain) != 2 {
		t.Fatalf("ProcessChain length = %d, want 2", len(chain))
	}
	if chain[0].Pid != 1234 {
		t.Errorf("ProcessChain[0].Pid = %d, want 1234", chain[0].Pid)
	}
	if chain[0].Username != "testuser" {
		t.Errorf("ProcessChain[0].Username = %q, want testuser", chain[0].Username)
	}
	if chain[1].Pid != 1 {
		t.Errorf("ProcessChain[1].Pid = %d, want 1", chain[1].Pid)
	}
}

func TestToSourceInfo_EmptyProcessChain(t *testing.T) {
	info := ProcessInfo{
		Command:  "test",
		Hostname: "host",
	}

	si := info.ToSourceInfo()
	if si.ProcessChain != nil {
		t.Error("ProcessChain should be nil when empty")
	}
}
