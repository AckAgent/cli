package main

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"github.com/ackagent/cli/internal/shared/transport"
)

var (
	bleList        bool
	bleListTimeout time.Duration
)

var bleCmd = &cobra.Command{
	Use:   "ble",
	Short: "Bluetooth utilities",
	RunE: func(cmd *cobra.Command, args []string) error {
		if bleList {
			return runBLEList(cmd, args)
		}
		return cmd.Help()
	},
}

var bleListCmd = &cobra.Command{
	Use:   "list",
	Short: "List AckAgent BLE devices",
	RunE:  runBLEList,
}

func init() {
	bleCmd.Flags().BoolVar(&bleList, "list", false, "List AckAgent BLE devices")
	bleCmd.PersistentFlags().DurationVar(&bleListTimeout, "timeout", transport.DefaultBLEScanTimeout, "Scan timeout (e.g. 5s)")
	bleCmd.AddCommand(bleListCmd)
	rootCmd.AddCommand(bleCmd)
}

func runBLEList(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), bleListTimeout)
	defer cancel()

	devices, err := transport.ScanBLEDevices(ctx, bleListTimeout)
	if err != nil {
		return err
	}

	sort.Slice(devices, func(i, j int) bool {
		if devices[i].Name == devices[j].Name {
			return devices[i].Address < devices[j].Address
		}
		return devices[i].Name < devices[j].Name
	})

	out := cmd.OutOrStdout()
	if len(devices) == 0 {
		fmt.Fprintln(out, "No AckAgent BLE devices found")
		return nil
	}

	fmt.Fprintln(out, "NAME\tADDRESS\tRSSI")
	for _, device := range devices {
		name := device.Name
		if name == "" {
			name = "(unknown)"
		}
		fmt.Fprintf(out, "%s\t%s\t%d\n", name, device.Address, device.RSSI)
	}

	return nil
}
