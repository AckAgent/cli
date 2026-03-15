package main

/*
#include <stdint.h>

typedef unsigned long CK_ULONG;

// KDF types
#define CKD_NULL                            0x00000001
#define CKD_SHA1_KDF                        0x00000002
#define CKD_SHA256_KDF                      0x00000006
*/
import "C"

import (
	"fmt"
	"strings"

	protocol "github.com/ackagent/api/go/protocol"
	"github.com/ackagent/cli/internal/shared/config"
	"github.com/ackagent/cli/internal/shared/sysinfo"
	"github.com/ackagent/cli/internal/shared/util"
)

// collectSigningDisplay builds a GenericDisplaySchema and SourceInfo for a PKCS#11 signing request.
func collectSigningDisplay(key *config.KeyMetadata, mechanism string, dataLen int) (*protocol.GenericDisplaySchema, *protocol.SourceInfo) {
	processInfo := sysinfo.GetProcessInfo()
	appName := getApplicationName(processInfo.ProcessChain)

	signIcon := "signature"
	fields := []protocol.DisplayField{
		{Label: "Key", Value: key.Label, Icon: &signIcon},
		{Label: "Public Key", Value: key.Hex(), Monospace: util.Ptr(true)},
		{Label: "Mechanism", Value: mechanism, Monospace: util.Ptr(true)},
		{Label: "Application", Value: appName},
		{Label: "Data Size", Value: fmt.Sprintf("%d bytes", dataLen)},
	}

	icon := "signature"
	historyTitle := "PKCS#11 Signature"
	subtitle := fmt.Sprintf("Sign with key: %s", key.Label)
	return &protocol.GenericDisplaySchema{
		Title:        "Sign data?",
		HistoryTitle: &historyTitle,
		Subtitle:     &subtitle,
		Icon:         &icon,
		Fields:       fields,
	}, processInfo.ToSourceInfo()
}

// collectDeriveDisplay builds a GenericDisplaySchema and SourceInfo for a PKCS#11 ECDH derive request.
func collectDeriveDisplay(key *config.KeyMetadata, mechanism string, kdf string) (*protocol.GenericDisplaySchema, *protocol.SourceInfo) {
	processInfo := sysinfo.GetProcessInfo()
	appName := getApplicationName(processInfo.ProcessChain)

	keyIcon := "key.horizontal"
	fields := []protocol.DisplayField{
		{Label: "Key", Value: key.Label, Icon: &keyIcon},
		{Label: "Public Key", Value: key.Hex(), Monospace: util.Ptr(true)},
		{Label: "Mechanism", Value: mechanism, Monospace: util.Ptr(true)},
		{Label: "KDF", Value: kdf},
		{Label: "Application", Value: appName},
	}

	icon := "key.horizontal"
	historyTitle := "ECDH Derive"
	subtitle := fmt.Sprintf("ECDH key agreement with key: %s", key.Label)
	return &protocol.GenericDisplaySchema{
		Title:        "ECDH Key Exchange?",
		HistoryTitle: &historyTitle,
		Subtitle:     &subtitle,
		Icon:         &icon,
		Fields:       fields,
	}, processInfo.ToSourceInfo()
}

// getApplicationName extracts the application name from the process chain
func getApplicationName(processChain []sysinfo.ProcessEntry) string {
	if len(processChain) == 0 {
		return "Unknown"
	}

	// Look for common application names in the process chain
	for _, entry := range processChain {
		cmd := strings.ToLower(entry.Command)

		// Check for well-known applications
		switch {
		case strings.Contains(cmd, "openssl"):
			return "OpenSSL"
		case strings.Contains(cmd, "firefox"):
			return "Firefox"
		case strings.Contains(cmd, "chrome"):
			return "Chrome"
		case strings.Contains(cmd, "safari"):
			return "Safari"
		case strings.Contains(cmd, "curl"):
			return "curl"
		case strings.Contains(cmd, "nginx"):
			return "nginx"
		case strings.Contains(cmd, "apache"):
			return "Apache"
		case strings.Contains(cmd, "java"):
			return "Java"
		case strings.Contains(cmd, "python"):
			return "Python"
		case strings.Contains(cmd, "node"):
			return "Node.js"
		case strings.Contains(cmd, "pkcs11-tool"):
			return "pkcs11-tool"
		case strings.Contains(cmd, "p11tool"):
			return "p11tool"
		}
	}

	// Return the first process in the chain if no known application is found
	if len(processChain) > 0 {
		// Extract just the binary name from the command
		cmd := processChain[0].Command
		parts := strings.Fields(cmd)
		if len(parts) > 0 {
			// Get basename
			path := parts[0]
			if idx := strings.LastIndex(path, "/"); idx >= 0 {
				return path[idx+1:]
			}
			return path
		}
	}

	return "Unknown"
}

// kdfToString converts a CKD_* constant to a readable string
func kdfToString(kdf C.CK_ULONG) string {
	switch kdf {
	case C.CKD_NULL:
		return "NULL (raw ECDH)"
	case C.CKD_SHA1_KDF:
		return "SHA1-KDF"
	case C.CKD_SHA256_KDF:
		return "SHA256-KDF"
	default:
		return fmt.Sprintf("CKD_0x%08X", uint32(kdf))
	}
}
