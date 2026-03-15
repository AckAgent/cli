package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

var profileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Manage configuration profiles",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var profileListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List all profiles",
	Run: func(cmd *cobra.Command, args []string) {
		profileList()
	},
}

var profileUseCmd = &cobra.Command{
	Use:     "use <name>",
	Aliases: []string{"switch"},
	Short:   "Switch to a profile",
	Args:    cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		profileUse(args[0])
	},
}

var profileShowCmd = &cobra.Command{
	Use:   "show [name]",
	Short: "Show profile details (default: active profile)",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		name := ""
		if len(args) > 0 {
			name = args[0]
		}
		profileShow(name)
	},
}

var profileRenameCmd = &cobra.Command{
	Use:     "rename <old> <new>",
	Aliases: []string{"mv"},
	Short:   "Rename a profile",
	Args:    cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		profileRename(args[0], args[1])
	},
}

var profileDeleteCmd = &cobra.Command{
	Use:     "delete <name>",
	Aliases: []string{"rm"},
	Short:   "Delete a profile",
	Args:    cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		profileDelete(args[0])
	},
}

func init() {
	profileCmd.AddCommand(profileListCmd)
	profileCmd.AddCommand(profileUseCmd)
	profileCmd.AddCommand(profileShowCmd)
	profileCmd.AddCommand(profileRenameCmd)
	profileCmd.AddCommand(profileDeleteCmd)
}

func profileList() {
	cfg := loadConfigOrDie()

	profiles := cfg.ListProfiles()
	if len(profiles) == 0 {
		fmt.Println("No profiles configured.")
		return
	}

	fmt.Println("Profiles:")
	for _, name := range profiles {
		p, _ := cfg.GetProfile(name)
		active := ""
		if name == cfg.ActiveProfile {
			active = " (active)"
		}
		loggedIn := ""
		if p != nil && p.IsLoggedIn() {
			loggedIn = " [logged in]"
		}
		fmt.Printf("  %s%s%s\n", name, active, loggedIn)
	}
}

func profileUse(name string) {
	cfg := loadConfigOrDie()

	if err := cfg.SetActiveProfile(name); err != nil {
		die("Error: %v", err)
	}

	if err := cfg.Save(); err != nil {
		die("Error saving config: %v", err)
	}

	fmt.Printf("Switched to profile: %s\n", name)
}

func profileShow(name string) {
	cfg := loadConfigOrDie()

	if name == "" {
		name = cfg.ActiveProfile
	}

	p, err := cfg.GetProfile(name)
	if err != nil {
		die("Error: %v", err)
	}

	fmt.Printf("Profile: %s", name)
	if name == cfg.ActiveProfile {
		fmt.Print(" (active)")
	}
	fmt.Println()
	fmt.Printf("  Relay URL: %s\n", p.RelayURL)

	if p.UserAccount != nil {
		fmt.Printf("  User ID: %s\n", p.UserAccount.UserID)
		fmt.Printf("  Logged in: %s\n", p.UserAccount.LoggedInAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("  SAS Verified: %v\n", p.UserAccount.SASVerified)
		fmt.Printf("  Devices: %d\n", len(p.UserAccount.Devices))
		for _, d := range p.UserAccount.Devices {
			primary := ""
			if d.IsPrimary {
				primary = " (primary)"
			}
			fmt.Printf("    - %s%s\n", d.DeviceName, primary)
		}
	} else {
		fmt.Println("  Not logged in")
	}

	if len(p.Keys) > 0 {
		fmt.Printf("  Signing Keys: %d\n", len(p.Keys))
		for _, k := range p.Keys {
			fmt.Printf("    - %s (%s)\n", k.Label, truncateFingerprint(k.Hex()))
		}
	}
}

func truncateFingerprint(fp string) string {
	// Show last 16 chars of fingerprint for brevity
	if len(fp) > 16 {
		return "..." + fp[len(fp)-16:]
	}
	return fp
}

func profileRename(oldName, newName string) {
	cfg := loadConfigOrDie()

	if err := cfg.RenameProfile(oldName, newName); err != nil {
		die("Error: %v", err)
	}

	if err := cfg.Save(); err != nil {
		die("Error saving config: %v", err)
	}

	fmt.Printf("Renamed profile '%s' to '%s'\n", oldName, newName)
}

func profileDelete(name string) {
	cfg := loadConfigOrDie()

	// Check if profile exists
	p, err := cfg.GetProfile(name)
	if err != nil {
		die("Error: %v", err)
	}

	// Warn if logged in
	if p.IsLoggedIn() {
		fmt.Printf("Warning: Profile '%s' is logged in. Deleting will remove credentials.\n", name)
	}

	// Confirm deletion
	fmt.Printf("Delete profile '%s'? [y/N] ", name)
	var response string
	fmt.Scanln(&response)
	if strings.ToLower(response) != "y" && strings.ToLower(response) != "yes" {
		fmt.Println("Cancelled.")
		return
	}

	if err := cfg.DeleteProfile(name); err != nil {
		die("Error: %v", err)
	}

	if err := cfg.Save(); err != nil {
		die("Error saving config: %v", err)
	}

	fmt.Printf("Deleted profile '%s'\n", name)
}
