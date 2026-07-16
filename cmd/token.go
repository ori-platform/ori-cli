// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/ori-platform/ori-cli/internal/output"
	"github.com/ori-platform/ori-cli/internal/token"
	"github.com/spf13/cobra"
)

// defaultDeviceKeyPath returns the operator-facing default path for the device
// Ed25519 public key used to verify offline tokens locally.
func defaultDeviceKeyPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "~/.ori/device.pub"
	}
	return filepath.Join(home, ".ori", "device.pub")
}

func newTokenCommand(state *rootState) *cobra.Command {
	cmd := &cobra.Command{Use: "token", Short: "Manage Ori offline tokens"}

	useCmd := &cobra.Command{
		Use:   "use <token>",
		Short: "Present an offline token to the local runtime without cloud access",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			keyPath, err := cmd.Flags().GetString("device-key")
			if err != nil {
				return fmt.Errorf("failed to read --device-key: %w", err)
			}
			deviceID, err := cmd.Flags().GetString("device-id")
			if err != nil {
				return fmt.Errorf("failed to read --device-id: %w", err)
			}
			result, err := state.useToken(args[0], token.UseOptions{
				DeviceKeyPath:    keyPath,
				ExpectedDeviceID: deviceID,
			})
			if err != nil {
				return err
			}
			if state.json {
				return output.JSON(state.stdout, result)
			}
			fmt.Fprintln(state.stdout, "offline token accepted for local runtime presentation")
			return nil
		},
	}
	useCmd.Flags().String("device-key", defaultDeviceKeyPath(), "path to device Ed25519 public key")
	useCmd.Flags().String("device-id", "", "expected device_id claim in the token")
	cmd.AddCommand(useCmd)

	for _, sub := range []string{"generate", "list", "revoke"} {
		subcommand := sub
		cmd.AddCommand(&cobra.Command{
			Use:   subcommand,
			Short: "Requires ori-cloud token service",
			RunE: func(_ *cobra.Command, _ []string) error {
				return notImplemented("token " + subcommand + " requires ori-cloud implementation")
			},
		})
	}
	return cmd
}
