package main

import (
	"github.com/ackagent/cli/internal/shared/log"
	"github.com/ackagent/cli/internal/shared/sysinfo"
)

// ProcessInfo extends sysinfo.ProcessInfo with SSH-specific fields.
// ToSourceInfo() is promoted from the embedded sysinfo.ProcessInfo.
type ProcessInfo struct {
	sysinfo.ProcessInfo
	AgentClients []sysinfo.ProcessEntry `json:"agentClients,omitempty"` // Processes connected to ssh-agent
}

var skLog = log.New("sk")

func init() {
	log.InitFromEnv()
}

func logDebug(format string, args ...interface{}) {
	skLog.Debug(format, args...)
}

func logError(format string, args ...interface{}) {
	skLog.Error(format, args...)
}
