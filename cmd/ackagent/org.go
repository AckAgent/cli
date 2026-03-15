package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ackagent/cli/internal/shared/config"
)

var orgCmd = &cobra.Command{
	Use:   "org",
	Short: "Manage organizations",
	Run: func(cmd *cobra.Command, args []string) {
		orgShowActive()
	},
}

var orgListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List all organizations",
	Run: func(cmd *cobra.Command, args []string) {
		orgList()
	},
}

var orgDefaultCmd = &cobra.Command{
	Use:   "default <identifier>",
	Short: "Set default organization (by UUID, local name, or emoji words)",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		orgSetDefault(args[0])
	},
}

var orgShowCmd = &cobra.Command{
	Use:   "show [identifier]",
	Short: "Show organization details (default: active org)",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		identifier := ""
		if len(args) > 0 {
			identifier = args[0]
		}
		orgShow(identifier)
	},
}

func init() {
	orgCmd.AddCommand(orgListCmd)
	orgCmd.AddCommand(orgDefaultCmd)
	orgCmd.AddCommand(orgShowCmd)
}

// orgShowActive shows the currently active organization.
func orgShowActive() {
	cfg := loadConfigOrDie()
	p, err := cfg.GetActiveProfile()
	if err != nil {
		die("Error: %v", err)
	}

	if len(p.Orgs) == 0 {
		fmt.Println("No organizations configured.")
		fmt.Println("Organizations are set up during login.")
		return
	}

	org, err := p.EffectiveOrg(cfg.WorkingOrg())
	if err != nil {
		die("Error: %v", err)
	}

	printOrgDetail(org, p.DefaultOrgID == org.OrgID)
}

// orgList lists all organizations in the active profile.
func orgList() {
	cfg := loadConfigOrDie()
	p, err := cfg.GetActiveProfile()
	if err != nil {
		die("Error: %v", err)
	}

	if len(p.Orgs) == 0 {
		fmt.Println("No organizations configured.")
		return
	}

	fmt.Println("Organizations:")
	for i, org := range p.Orgs {
		isDefault := p.DefaultOrgID == org.OrgID
		marker := ""
		if isDefault {
			marker = " [default]"
		}
		name := org.DisplayName()
		fmt.Printf("  %d. %s (%s)%s\n", i+1, org.Emojis(), name, marker)
		fmt.Printf("     %d signing key(s)\n", len(org.Keys))
	}
}

// orgSetDefault sets the default organization.
func orgSetDefault(identifier string) {
	cfg := loadConfigOrDie()
	p, err := cfg.GetActiveProfile()
	if err != nil {
		die("Error: %v", err)
	}

	org, err := p.ResolveOrg(identifier)
	if err != nil {
		die("Error: %v", err)
	}

	p.DefaultOrgID = org.OrgID
	if err := cfg.Save(); err != nil {
		die("Error saving config: %v", err)
	}

	fmt.Printf("Default organization set to: %s (%s)\n", org.Emojis(), org.DisplayName())
}

// orgShow shows detailed information about an organization.
func orgShow(identifier string) {
	cfg := loadConfigOrDie()
	p, err := cfg.GetActiveProfile()
	if err != nil {
		die("Error: %v", err)
	}

	if len(p.Orgs) == 0 {
		fmt.Println("No organizations configured.")
		return
	}

	var org *config.OrgConfig
	if identifier == "" {
		org, err = p.EffectiveOrg(cfg.WorkingOrg())
		if err != nil {
			die("Error: %v", err)
		}
	} else {
		org, err = p.ResolveOrg(identifier)
		if err != nil {
			die("Error: %v", err)
		}
	}

	printOrgDetail(org, p.DefaultOrgID == org.OrgID)
}

// printOrgDetail prints detailed information about an organization.
func printOrgDetail(org *config.OrgConfig, isDefault bool) {
	fmt.Printf("Organization: %s\n", org.Emojis())
	fmt.Printf("  Words:   %s\n", org.EmojiWords())
	if org.LocalName != "" {
		fmt.Printf("  Name:    %s\n", org.LocalName)
	}
	fmt.Printf("  ID:      %s\n", org.OrgID)
	if isDefault {
		fmt.Printf("  Status:  default\n")
	}
	fmt.Printf("  Keys:    %d\n", len(org.Keys))

	if len(org.Keys) > 0 {
		fmt.Println()
		fmt.Println("  Signing Keys:")
		for i, key := range org.Keys {
			fmt.Printf("    %d. %s (%s)\n", i+1, key.Label, truncateFingerprint(key.Hex()))
			if key.StorageType != "" {
				storageDesc := string(key.StorageType)
				switch key.StorageType {
				case config.StorageTypeSecureEnclave:
					storageDesc = "Secure Enclave (hardware-backed)"
				case config.StorageTypeICloudKeychain:
					storageDesc = "iCloud Keychain (synced)"
				case config.StorageTypeSoftwareLocal:
					storageDesc = "Local software"
				}
				fmt.Printf("       Storage: %s\n", storageDesc)
			}
		}
	}
}
