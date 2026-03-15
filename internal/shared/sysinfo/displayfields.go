package sysinfo

import (
	protocol "github.com/ackagent/api/go/protocol"
)

// ToSourceInfo converts ProcessInfo into a protocol.SourceInfo struct
// suitable for inclusion in any CLI-originated request payload.
func (p ProcessInfo) ToSourceInfo() *protocol.SourceInfo {
	si := &protocol.SourceInfo{
		Hostname: &p.Hostname,
		LocalIp:  &p.LocalIP,
		Username: &p.Username,
		Command:  &p.Command,
	}
	if len(p.ProcessChain) > 0 {
		chain := make([]protocol.ProcessEntry, len(p.ProcessChain))
		for i, e := range p.ProcessChain {
			chain[i] = protocol.ProcessEntry{
				Pid:      int32(e.PID),
				Username: e.Username,
				Command:  e.Command,
			}
		}
		si.ProcessChain = &chain
	}
	return si
}
