package main

import (
	"testing"

	"github.com/ackagent/cli/internal/shared/config"
	"github.com/ackagent/cli/internal/shared/sysinfo"
)

func TestGetApplicationName_EmptyChain(t *testing.T) {
	got := bridgeGetApplicationName(nil)
	if got != "Unknown" {
		t.Errorf("getApplicationName(nil) = %q, want %q", got, "Unknown")
	}
}

func TestGetApplicationName_KnownApps(t *testing.T) {
	tests := []struct {
		command string
		want    string
	}{
		{"openssl s_client", "OpenSSL"},
		{"/usr/bin/firefox", "Firefox"},
		{"google-chrome --headless", "Chrome"},
		{"/Applications/Safari.app/Contents/MacOS/Safari", "Safari"},
		{"curl https://example.com", "curl"},
		{"/usr/sbin/nginx", "nginx"},
		{"apache2", "Apache"},
		{"java -jar app.jar", "Java"},
		{"python3 script.py", "Python"},
		{"node server.js", "Node.js"},
		{"pkcs11-tool --list-objects", "pkcs11-tool"},
		{"p11tool --list-tokens", "p11tool"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			chain := []sysinfo.ProcessEntry{
				{PID: 1000, Command: tt.command},
			}
			got := bridgeGetApplicationName(chain)
			if got != tt.want {
				t.Errorf("getApplicationName(%q) = %q, want %q", tt.command, got, tt.want)
			}
		})
	}
}

func TestGetApplicationName_UnknownProcess(t *testing.T) {
	chain := []sysinfo.ProcessEntry{
		{PID: 1000, Command: "/usr/local/bin/custom-app --flag"},
	}
	got := bridgeGetApplicationName(chain)
	if got != "custom-app" {
		t.Errorf("getApplicationName(custom-app) = %q, want %q", got, "custom-app")
	}
}

func TestGetApplicationName_SimpleCommand(t *testing.T) {
	chain := []sysinfo.ProcessEntry{
		{PID: 1000, Command: "myapp"},
	}
	got := bridgeGetApplicationName(chain)
	if got != "myapp" {
		t.Errorf("getApplicationName(myapp) = %q, want %q", got, "myapp")
	}
}

func TestGetApplicationName_MatchesLaterInChain(t *testing.T) {
	chain := []sysinfo.ProcessEntry{
		{PID: 1000, Command: "bash"},
		{PID: 1001, Command: "/usr/bin/openssl enc"},
	}
	got := bridgeGetApplicationName(chain)
	if got != "OpenSSL" {
		t.Errorf("expected OpenSSL from chain, got %q", got)
	}
}

func TestParseFingerprint_Lengths(t *testing.T) {
	tests := []struct {
		input string
		want  int // expected byte length
	}{
		{"AABBCCDD", 4},
		{"AA BB CC DD", 4},
		{"AA:BB:CC:DD", 4},
		{"", 0},
	}

	for _, tt := range tests {
		got := bridgeParseFingerprint(tt.input)
		if len(got) != tt.want {
			t.Errorf("parseFingerprint(%q) length = %d, want %d", tt.input, len(got), tt.want)
		}
	}
}

func TestParseFingerprint_Values(t *testing.T) {
	got := bridgeParseFingerprint("AABB")
	if len(got) != 2 || got[0] != 0xAA || got[1] != 0xBB {
		t.Errorf("parseFingerprint(AABB) = %x, want aabb", got)
	}
}

func TestParseHexByte_Values(t *testing.T) {
	tests := []struct {
		input string
		want  byte
	}{
		{"00", 0x00},
		{"FF", 0xFF},
		{"ff", 0xFF},
		{"AB", 0xAB},
		{"1a", 0x1A},
	}

	for _, tt := range tests {
		got, n := bridgeParseHexByte(tt.input)
		if got != tt.want {
			t.Errorf("parseHexByte(%q) = 0x%02X, want 0x%02X", tt.input, got, tt.want)
		}
		if n != 2 {
			t.Errorf("parseHexByte(%q) consumed %d, want 2", tt.input, n)
		}
	}
}

func TestCollectSigningDisplay_Fields(t *testing.T) {
	key := &config.KeyMetadata{
		Label:     "Test Key",
		PublicKey: []byte{0x02, 0x01, 0x02, 0x03},
		Algorithm: "ecdsa",
	}
	title, fieldCount := bridgeCollectSigningDisplay(key, "CKM_ECDSA", 32)
	if title != "Sign data?" {
		t.Errorf("title = %q, want %q", title, "Sign data?")
	}
	if fieldCount != 5 {
		t.Errorf("fieldCount = %d, want 5", fieldCount)
	}
}

func TestCollectDeriveDisplay_Fields(t *testing.T) {
	key := &config.KeyMetadata{
		Label:     "ECDH Key",
		PublicKey: []byte{0x02, 0x01, 0x02, 0x03},
		Algorithm: "ecdsa",
	}
	title, fieldCount := bridgeCollectDeriveDisplay(key, "CKM_ECDH1_DERIVE", "SHA256-KDF")
	if title != "ECDH Key Exchange?" {
		t.Errorf("title = %q, want %q", title, "ECDH Key Exchange?")
	}
	if fieldCount != 5 {
		t.Errorf("fieldCount = %d, want 5", fieldCount)
	}
}
