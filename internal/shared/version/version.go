// Package version provides the application version set at build time.
package version

// Version is set at build time via ldflags:
// -X github.com/ackagent/cli/internal/shared/version.Version=<version>
var Version = "dev"
