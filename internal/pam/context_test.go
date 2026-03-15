package pam

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewAuthContext(t *testing.T) {
	ctx := NewAuthContext("testuser", "sshd")

	assert.Equal(t, "testuser", ctx.LocalUsername)
	assert.Equal(t, "sshd", ctx.PAMService)
	assert.NotEmpty(t, ctx.Hostname)
	assert.Greater(t, ctx.Timestamp, int64(0))
}

func TestGatherContext(t *testing.T) {
	pamEnv := &PAMEnv{
		TTY:        "/dev/pts/0",
		RemoteHost: "192.168.1.100",
	}

	ctx := GatherContext("testuser", "sshd", pamEnv)

	assert.Equal(t, "testuser", ctx.LocalUsername)
	assert.Equal(t, "sshd", ctx.PAMService)
	assert.Equal(t, "/dev/pts/0", ctx.TTY)
	assert.Equal(t, "192.168.1.100", ctx.RemoteHost)
	assert.NotEmpty(t, ctx.Hostname)
	assert.NotNil(t, ctx.SSHAuthSockPresent)
}

func TestGatherContext_NilPAMEnv(t *testing.T) {
	ctx := GatherContext("testuser", "sudo", nil)

	assert.Equal(t, "testuser", ctx.LocalUsername)
	assert.Equal(t, "sudo", ctx.PAMService)
	assert.NotEmpty(t, ctx.Hostname)
}

func TestBuildSourceInfo(t *testing.T) {
	si := buildSourceInfo()

	assert.NotNil(t, si)
	assert.NotNil(t, si.Hostname)
	assert.NotEmpty(t, *si.Hostname)

	// On a real system, we should have process chain entries
	if si.ProcessChain != nil && len(*si.ProcessChain) > 0 {
		chain := *si.ProcessChain
		lastEntry := chain[len(chain)-1]
		assert.NotEmpty(t, lastEntry.Command)
		assert.Greater(t, lastEntry.Pid, int32(0))
	}
}

func TestGetOSVersion(t *testing.T) {
	version := getOSVersion()
	// Should return something on most systems
	// (empty string is acceptable if neither /etc/os-release nor uname works)
	t.Logf("OS version: %s", version)
}
