// Package main provides the ackagent-audit CLI entry point.
// This tool allows customers to independently verify their audit chain exports
// without trusting AckAgent's servers.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ackagent/cli/internal/audit"
)

var version = "dev"

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "ackagent-audit",
	Short: "Verify and analyze AckAgent audit chain exports",
	Long: `ackagent-audit is a tool for independently verifying the integrity
of AckAgent audit chain exports. It allows you to:

- Verify chain integrity (no keys needed)
- Verify Merkle tree consistency
- Check entries against transparency logs
- Decrypt payloads with your organization's private key
- Query and analyze audit data

All verification can be done offline without trusting AckAgent's servers.`,
	Version: version,
}

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify audit chain integrity",
	Long:  "Verify the cryptographic integrity of audit chain exports.",
}

var verifyChainCmd = &cobra.Command{
	Use:   "chain <export-file>",
	Short: "Verify all chains in an export file",
	Long: `Verify the integrity of all chains in an exported audit chain file.

This checks:
- Hash integrity: Each entry's hash matches its contents
- Chain linkage: prev_hash links form an unbroken chain
- Sequence continuity: No gaps in sequence numbers
- Device signatures: Hardware-backed signatures are valid (if keys available)
- Merkle trees: Roots are computed correctly
- Transparency log: No tampering in append-only log

No private keys are needed for verification.`,
	Args: cobra.ExactArgs(1),
	RunE: runVerifyChain,
}

var verifyTreeCmd = &cobra.Command{
	Use:   "tree <tree-file>",
	Short: "Verify a single Merkle tree",
	Long:  "Verify the integrity of a single Merkle tree export.",
	Args:  cobra.ExactArgs(1),
	RunE:  runVerifyTree,
}

var decryptCmd = &cobra.Command{
	Use:   "decrypt <export-file>",
	Short: "Decrypt payloads in an export",
	Long: `Decrypt the encrypted payloads in an audit chain export.

This requires your organization's private key.`,
	Args: cobra.ExactArgs(1),
	RunE: runDecrypt,
}

var queryCmd = &cobra.Command{
	Use:   "query <export-file>",
	Short: "Query audit data",
	Long:  "Query and filter audit data from an export file.",
	Args:  cobra.ExactArgs(1),
	RunE:  runQuery,
}

// Flags
var (
	keyFile    string
	outputFile string
	userID     string
	deviceID   string
	requestID  string
	fromDate   string
	toDate     string
	verbose    bool
	jsonOutput bool
)

func init() {
	// Add subcommands
	rootCmd.AddCommand(verifyCmd)
	rootCmd.AddCommand(decryptCmd)
	rootCmd.AddCommand(queryCmd)

	verifyCmd.AddCommand(verifyChainCmd)
	verifyCmd.AddCommand(verifyTreeCmd)

	// Global flags
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "Output results as JSON")

	// Decrypt flags
	decryptCmd.Flags().StringVarP(&keyFile, "key", "k", "", "Path to organization private key file")
	decryptCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file for decrypted data")
	decryptCmd.MarkFlagRequired("key")

	// Query flags
	queryCmd.Flags().StringVar(&userID, "user", "", "Filter by user ID")
	queryCmd.Flags().StringVar(&deviceID, "device", "", "Filter by device ID")
	queryCmd.Flags().StringVar(&requestID, "request", "", "Filter by request ID")
	queryCmd.Flags().StringVar(&fromDate, "from", "", "Start date (RFC3339 format)")
	queryCmd.Flags().StringVar(&toDate, "to", "", "End date (RFC3339 format)")
}

func runVerifyChain(cmd *cobra.Command, args []string) error {
	exportFile := args[0]

	// Read export file
	data, err := os.ReadFile(exportFile)
	if err != nil {
		return fmt.Errorf("read export file: %w", err)
	}

	var export audit.ChainExport
	if err := json.Unmarshal(data, &export); err != nil {
		return fmt.Errorf("parse export file: %w", err)
	}

	// Create verifier
	verifier := audit.NewVerifier()

	// Run verification
	result := verifier.VerifyExport(&export)

	// Output results
	if jsonOutput {
		output, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(output))
	} else {
		printVerificationResult(result, &export)
	}

	if !result.Valid {
		return fmt.Errorf("verification failed with %d errors", len(result.Errors))
	}

	return nil
}

func runVerifyTree(cmd *cobra.Command, args []string) error {
	treeFile := args[0]

	// Read tree file
	data, err := os.ReadFile(treeFile)
	if err != nil {
		return fmt.Errorf("read tree file: %w", err)
	}

	var tree audit.MerkleTree
	if err := json.Unmarshal(data, &tree); err != nil {
		return fmt.Errorf("parse tree file: %w", err)
	}

	// Create verifier
	verifier := audit.NewVerifier()

	// Verify tree
	if err := verifier.VerifyMerkleTree(&tree); err != nil {
		if jsonOutput {
			output, _ := json.MarshalIndent(map[string]interface{}{
				"valid": false,
				"error": err.Error(),
			}, "", "  ")
			fmt.Println(string(output))
		} else {
			fmt.Printf("❌ Merkle tree verification failed: %v\n", err)
		}
		return err
	}

	if jsonOutput {
		output, _ := json.MarshalIndent(map[string]interface{}{
			"valid":   true,
			"tree_id": tree.TreeID,
		}, "", "  ")
		fmt.Println(string(output))
	} else {
		fmt.Printf("✓ Merkle tree %s verified successfully\n", tree.TreeID)
	}

	return nil
}

func runDecrypt(cmd *cobra.Command, args []string) error {
	// TODO: Implement decryption using organization's private key
	return fmt.Errorf("decryption not yet implemented - requires BYOK key management integration")
}

func runQuery(cmd *cobra.Command, args []string) error {
	exportFile := args[0]

	// Read export file
	data, err := os.ReadFile(exportFile)
	if err != nil {
		return fmt.Errorf("read export file: %w", err)
	}

	var export audit.ChainExport
	if err := json.Unmarshal(data, &export); err != nil {
		return fmt.Errorf("parse export file: %w", err)
	}

	// Filter results
	var results []interface{}

	// Query device entries
	for _, entry := range export.DeviceEntries {
		if deviceID != "" && entry.DeviceID != deviceID {
			continue
		}
		results = append(results, entry)
	}

	// Query request entries
	for _, entry := range export.RequestEntries {
		if requestID != "" && entry.RequestID != requestID {
			continue
		}
		if userID != "" && entry.RequesterID != userID {
			continue
		}
		results = append(results, entry)
	}

	// Output results
	if jsonOutput {
		output, _ := json.MarshalIndent(map[string]interface{}{
			"count":   len(results),
			"results": results,
		}, "", "  ")
		fmt.Println(string(output))
	} else {
		fmt.Printf("Found %d matching entries\n", len(results))
		for i, r := range results {
			if i >= 10 && !verbose {
				fmt.Printf("... and %d more (use --verbose to see all)\n", len(results)-10)
				break
			}
			output, _ := json.MarshalIndent(r, "", "  ")
			fmt.Println(string(output))
		}
	}

	return nil
}

func printVerificationResult(result *audit.VerificationResult, export *audit.ChainExport) {
	if result.Valid {
		fmt.Printf("✓ All %d entries verified. No tampering detected.\n", result.EntriesCount)
	} else {
		fmt.Printf("❌ Verification failed with %d errors\n", len(result.Errors))
	}

	// Print summary
	fmt.Printf("\nSummary:\n")
	fmt.Printf("  Organization: %s\n", export.OrgID)
	fmt.Printf("  Exported at:  %s\n", export.ExportedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Time range:   %s to %s\n",
		export.FromTime.Format("2006-01-02"),
		export.ToTime.Format("2006-01-02"))
	fmt.Printf("  Device entries: %d\n", len(export.DeviceEntries))
	fmt.Printf("  Request entries: %d\n", len(export.RequestEntries))
	fmt.Printf("  Merkle trees: %d\n", len(export.MerkleTrees))
	fmt.Printf("  Transparency entries: %d\n", len(export.TransparencyEntries))

	// Print errors
	if len(result.Errors) > 0 {
		fmt.Printf("\nErrors:\n")
		for _, err := range result.Errors {
			fmt.Printf("  - [%s] seq=%d: %s\n", err.ErrorType, err.Sequence, err.Description)
		}
	}

	// Print warnings
	if len(result.Warnings) > 0 && verbose {
		fmt.Printf("\nWarnings:\n")
		for _, warn := range result.Warnings {
			fmt.Printf("  - %s\n", warn)
		}
	}
}
