// ackagent is a unified CLI for AckAgent desktop operations.
// It provides subcommands for login, GPG signing, and Claude Code approval hooks.
//
// Usage:
//
//	ackagent login   # OAuth login and SAS verification
//	ackagent gpg     # GPG-compatible signing
//	ackagent hook    # Approval hooks for various apps
//	ackagent version # Show version
//	ackagent help    # Show help
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/ackagent/cli/internal/shared/config"
	"github.com/ackagent/cli/internal/shared/log"
	"github.com/ackagent/cli/internal/shared/version"
)

// Global flags accessible to all subcommands via persistent flags
var (
	cfgDir    string
	profile   string
	orgFlag   string
	logLevel  string
	bleDevice string
)

var rootCmd = &cobra.Command{
	Use:     "ackagent",
	Short:   "AckAgent CLI for hardware-backed signing",
	Version: version.Version,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Get values from Viper (merges flag > env > default)
		cfgDir = viper.GetString("config-dir")
		profile = viper.GetString("profile")
		orgFlag = viper.GetString("org")
		logLevel = viper.GetString("log-level")
		bleDevice = viper.GetString("ble-device")

		// Apply config dir override first (before any config loading)
		if cfgDir != "" {
			config.SetConfigDir(cfgDir)
		}

		// Apply log level from flag/env (overrides InitFromEnv defaults)
		if logLevel != "" {
			log.SetLevelFromString(logLevel)
		}

		// Normalize BLE device flag (trimmed in PersistentPreRun, applied to config in loadConfigWithProfile).
		bleDevice = strings.TrimSpace(bleDevice)
	},
	Run: func(cmd *cobra.Command, args []string) {
		// Default action: show help
		cmd.Help()
	},
}

func init() {
	rootCmd.SetVersionTemplate("{{.Version}}\n")

	// Persistent flags - available to ALL subcommands
	rootCmd.PersistentFlags().StringVarP(&cfgDir, "config-dir", "c", "", "Use alternative config directory")
	rootCmd.PersistentFlags().StringVarP(&profile, "profile", "p", "", "Use specified profile (overrides active)")
	rootCmd.PersistentFlags().StringVar(&orgFlag, "org", "", "Use specified organization (UUID, local name, or emoji words)")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "", "Set log level: debug, info, warn, error")
	rootCmd.PersistentFlags().StringVar(&bleDevice, "ble-device", "", "BLE device name or address for local transport")

	// Bind flags to Viper with ACKAGENT_ prefix for env vars
	// This enables: ACKAGENT_CONFIG_DIR, ACKAGENT_PROFILE, ACKAGENT_LOG_LEVEL
	viper.SetEnvPrefix("ACKAGENT")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_")) // config-dir -> CONFIG_DIR
	viper.AutomaticEnv()

	// Bind each persistent flag so Viper merges flag > env > default
	viper.BindPFlag("config-dir", rootCmd.PersistentFlags().Lookup("config-dir"))
	viper.BindPFlag("profile", rootCmd.PersistentFlags().Lookup("profile"))
	viper.BindPFlag("org", rootCmd.PersistentFlags().Lookup("org"))
	viper.BindPFlag("log-level", rootCmd.PersistentFlags().Lookup("log-level"))
	viper.BindPFlag("ble-device", rootCmd.PersistentFlags().Lookup("ble-device"))

	// Add subcommands
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(gpgCmd)
	rootCmd.AddCommand(ageCmd)
	rootCmd.AddCommand(sshCmd)
	rootCmd.AddCommand(keysCmd)
	rootCmd.AddCommand(hookCmd)
	rootCmd.AddCommand(profileCmd)
	rootCmd.AddCommand(orgCmd)
}

func main() {
	// Initialize log level from environment
	log.InitFromEnv()

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// die prints an error message to stderr and exits with code 1.
func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

// loadConfigOrDie loads the config file and applies profile and org overrides if set.
func loadConfigOrDie() *config.Config {
	return loadConfigWithProfile("")
}

// loadConfigWithProfile loads config and applies the given profile override.
// If profile is empty, it uses the active profile.
// Also applies the --org / ACKAGENT_ORG override if set.
func loadConfigWithProfile(profileOverride string) *config.Config {
	cfg, err := config.Load()
	if err != nil {
		die("Error loading config: %v", err)
	}

	if profileOverride != "" {
		if err := cfg.SetWorkingProfile(profileOverride); err != nil {
			die("Error: profile %q not found", profileOverride)
		}
	}

	// Apply org override from --org flag or ACKAGENT_ORG env var
	if orgFlag != "" {
		cfg.SetWorkingOrg(orgFlag)
	}

	// Apply BLE transport settings from --ble-device flag
	if bleDevice != "" {
		cfg.BLEEnabled = true
		cfg.BLEDevice = bleDevice
	}

	return cfg
}
