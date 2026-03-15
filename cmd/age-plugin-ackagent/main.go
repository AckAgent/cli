// age-plugin-ackagent is an age plugin that uses iOS-stored X25519 keys.
//
// Installation:
//
//	go build -o age-plugin-ackagent ./cli/cmd/age-plugin-ackagent
//	mv age-plugin-ackagent ~/.local/bin/  # or anywhere in PATH
//
// The binary must be named "age-plugin-ackagent" and be in the PATH.
//
// Usage:
//
//	# Generate a key (on iOS)
//	ackagent age keygen
//
//	# Get recipient for encryption
//	ackagent age recipient
//	# -> age1ackagent1...
//
//	# Encrypt a file (anyone can do this)
//	age -r age1ackagent1... -o secret.age secret.txt
//
//	# Decrypt (requires iOS approval)
//	age -d -i ~/.config/ackagent/age-identity.txt secret.age > secret.txt
package main

import (
	"flag"
	"fmt"
	"os"

	"filippo.io/age"
	"filippo.io/age/plugin"
	ackage "github.com/ackagent/cli/internal/age"
)

// debugEnabled reports whether ACKAGENT_DEBUG is set to a non-empty value.
func debugEnabled() bool {
	return os.Getenv("ACKAGENT_DEBUG") != ""
}

// debugLogPath returns the UID-namespaced debug log file path.
func debugLogPath() string {
	return fmt.Sprintf("/tmp/age-plugin-ackagent-%d.log", os.Getuid())
}

// debugLog writes to stderr and a debug file when ACKAGENT_DEBUG is set.
// The log file is created with mode 0600 and includes the UID in the filename
// to prevent cross-user information leakage.
func debugLog(format string, args ...interface{}) {
	if !debugEnabled() {
		return
	}
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintln(os.Stderr, msg)
	if f, err := os.OpenFile(debugLogPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600); err == nil {
		f.WriteString(msg + "\n")
		f.Close()
	}
}

func main() {
	// Debug: announce plugin startup
	debugLog("[age-plugin-ackagent] STARTUP: args=%v", os.Args)

	// Create the plugin
	p, err := plugin.New("ackagent")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create plugin: %v\n", err)
		os.Exit(1)
	}

	// Register recipient handler - called when encrypting to age1ackagent1...
	// The data parameter contains the 32-byte public key
	p.HandleRecipient(func(data []byte) (age.Recipient, error) {
		if len(data) != 32 {
			return nil, fmt.Errorf("invalid recipient data length: %d", len(data))
		}
		return &ackage.Recipient{PublicKey: data}, nil
	})

	// Register identity handler - called when decrypting with AGE-PLUGIN-ACKAGENT-...
	// The data parameter contains the key fingerprint as bytes
	p.HandleIdentity(func(data []byte) (age.Identity, error) {
		fingerprint := string(data)

		// Debug: log to stderr for visibility in tests
		debugLog("[age-plugin-ackagent] identity handler called, fingerprint=%q\n", fingerprint)
		debugLog("[age-plugin-ackagent] ACKAGENT_CONFIG_DIR env=%q\n", os.Getenv("ACKAGENT_CONFIG_DIR"))
		debugLog("[age-plugin-ackagent] ConfigDir()=%s\n", ackage.ConfigDir())
		debugLog("[age-plugin-ackagent] ConfigPath()=%s\n", ackage.ConfigPath())
		debugLog("[age-plugin-ackagent] ProfilesDir()=%s\n", ackage.ProfilesDir())

		// Load config to find the key
		cfg, err := ackage.LoadConfig()
		if err != nil {
			debugLog("[age-plugin-ackagent] failed to load config: %v\n", err)
			return nil, fmt.Errorf("failed to load config: %v", err)
		}

		debugLog("[age-plugin-ackagent] config loaded, relay=%s, activeProfile=%s\n", cfg.RelayURL(), cfg.EffectiveProfile())

		if !cfg.IsLoggedIn() {
			debugLog("[age-plugin-ackagent] not logged in")
			return nil, fmt.Errorf("not logged in: run 'ackagent login' first")
		}

		debugLog("[age-plugin-ackagent] user is logged in")

		// Debug: list all keys in config
		allKeys := cfg.Keys()
		debugLog("[age-plugin-ackagent] config has %d keys\n", len(allKeys))
		for i, k := range allKeys {
			debugLog("[age-plugin-ackagent]   key[%d]: purpose=%s pubKeyHex=%s label=%s\n", i, k.Purpose, k.Hex(), k.Label)
		}

		// Find the age key - either by fingerprint or by purpose
		var key *ackage.KeyMetadata
		if fingerprint != "" {
			key, _ = cfg.FindKey(fingerprint)
			if key != nil {
				debugLog("[age-plugin-ackagent] found key by fingerprint: %s\n", fingerprint)
			}
		}
		if key == nil {
			key = cfg.FindKeyByPurpose(ackage.KeyPurposeAge)
			if key != nil {
				debugLog("[age-plugin-ackagent] found key by purpose=age")
			}
		}
		if key == nil {
			debugLog("[age-plugin-ackagent] no age key enrolled (searched fp=%q and purpose=age)\n", fingerprint)
			return nil, fmt.Errorf("no age key enrolled")
		}

		debugLog("[age-plugin-ackagent] found key: %s\n", key.Hex())

		// Create identity with unwrap function
		unwrapFunc := ackage.MakeUnwrapFunc(cfg, key, "encrypted file", 0)
		identity := ackage.IdentityFromKey(key, cfg, unwrapFunc)

		debugLog("[age-plugin-ackagent] identity created, ready to unwrap")

		return identity, nil
	})

	// Register flags and run
	p.RegisterFlags(flag.CommandLine)
	flag.Parse()
	os.Exit(p.Main())
}
