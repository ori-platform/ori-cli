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

// defaultTokenKeyPath returns the operator-facing default path for the offline
// token trust-anchor Ed25519 public key. This is the key that signs tokens, not
// the device identity key.
func defaultTokenKeyPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "~/.ori/offline-token.pub"
	}
	return filepath.Join(home, ".ori", "offline-token.pub")
}

func newTokenCommand(state *rootState) *cobra.Command {
	cmd := &cobra.Command{Use: "token", Short: "Manage Ori offline tokens"}

	useCmd := &cobra.Command{
		Use:   "use <token>",
		Short: "Present an offline token to the local runtime without cloud access",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			keyPath, err := cmd.Flags().GetString("token-key")
			if err != nil {
				return fmt.Errorf("failed to read --token-key: %w", err)
			}
			deviceID, err := cmd.Flags().GetString("device-id")
			if err != nil {
				return fmt.Errorf("failed to read --device-id: %w", err)
			}
			result, err := state.useToken(args[0], token.UseOptions{
				TokenKeyPath:     keyPath,
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
	useCmd.Flags().String("token-key", defaultTokenKeyPath(), "path to offline token Ed25519 trust-anchor public key")
	useCmd.Flags().String("device-id", "", "expected device_id claim in the token (required)")
	_ = useCmd.MarkFlagRequired("device-id")
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
