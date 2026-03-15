package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDebugEnabled_Off(t *testing.T) {
	t.Setenv("ACKAGENT_DEBUG", "")
	assert.False(t, debugEnabled())
}

func TestDebugEnabled_On(t *testing.T) {
	t.Setenv("ACKAGENT_DEBUG", "1")
	assert.True(t, debugEnabled())
}

func TestDebugLogPath_ContainsUID(t *testing.T) {
	path := debugLogPath()
	uid := os.Getuid()
	assert.Contains(t, path, "/tmp/age-plugin-ackagent-")
	assert.Contains(t, path, string(rune('0'+uid%10))) // at minimum the last digit
	assert.Equal(t, filepath.Dir(path), "/tmp")
}

func TestDebugLog_NoFileWhenDisabled(t *testing.T) {
	t.Setenv("ACKAGENT_DEBUG", "")

	// Use a unique path to verify no file is created
	logPath := debugLogPath()
	os.Remove(logPath) // clean up if exists

	debugLog("should not appear: %s", "test")

	_, err := os.Stat(logPath)
	assert.True(t, os.IsNotExist(err), "log file should not be created when ACKAGENT_DEBUG is unset")
}

func TestDebugLog_WritesWhenEnabled(t *testing.T) {
	t.Setenv("ACKAGENT_DEBUG", "1")

	logPath := debugLogPath()
	os.Remove(logPath) // clean start
	defer os.Remove(logPath)

	debugLog("test message: %s", "hello")

	data, err := os.ReadFile(logPath)
	require.NoError(t, err)
	assert.Contains(t, string(data), "test message: hello")
}

func TestDebugLog_FilePermissions(t *testing.T) {
	t.Setenv("ACKAGENT_DEBUG", "1")

	logPath := debugLogPath()
	os.Remove(logPath) // clean start
	defer os.Remove(logPath)

	debugLog("permissions test")

	info, err := os.Stat(logPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm(),
		"log file should have 0600 permissions")
}
