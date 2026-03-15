// Package sysinfo provides utilities for collecting system information
// such as hostname and local IP addresses.
package sysinfo

import (
	"net"
	"os"
)

// GetHostname returns the system hostname.
func GetHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return ""
	}
	return hostname
}

// GetLocalIP returns the first non-loopback IPv4 address.
func GetLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipv4 := ipnet.IP.To4(); ipv4 != nil {
				return ipv4.String()
			}
		}
	}

	return ""
}
