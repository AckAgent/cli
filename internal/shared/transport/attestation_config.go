package transport

import "os"

// AllowSkipAttestation is set to "true" only in development builds via ldflags:
//
//	-X github.com/ackagent/cli/internal/shared/transport.AllowSkipAttestation=true
var AllowSkipAttestation = "false"

// SkipAttestationRequested returns true only if both the build allows skipping
// AND the environment variable is set.
func SkipAttestationRequested() bool {
	return AllowSkipAttestation == "true" && os.Getenv("SKIP_VERIFY_ATTESTATION") == "true"
}
