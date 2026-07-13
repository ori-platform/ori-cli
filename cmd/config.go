// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"

	"github.com/ori-platform/ori-cli/internal/bridge"
	"github.com/spf13/cobra"
)

func newConfigCommand(state *rootState) *cobra.Command {
	cmd := &cobra.Command{Use: "config", Short: "Inspect and validate runtime configuration"}

	validateCmd := &cobra.Command{
		Use:   "validate [path]",
		Short: "Validate ori.yaml through the runtime bridge",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := cmd.Flags().GetString("path")
			if err != nil {
				return fmt.Errorf("failed to read --path: %w", err)
			}
			if len(args) > 0 {
				path = args[0]
			}
			return bridgeBacked(state, "config", "validate", "--path", path)
		},
	}
	validateCmd.Flags().String("path", bridge.DefaultConfigPath, "path to ori.yaml")

	showCmd := &cobra.Command{
		Use:   "show [path]",
		Short: "Show normalized runtime configuration through the runtime bridge",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := cmd.Flags().GetString("path")
			if err != nil {
				return fmt.Errorf("failed to read --path: %w", err)
			}
			if len(args) > 0 {
				path = args[0]
			}
			return bridgeBacked(state, "config", "show", "--path", path)
		},
	}
	showCmd.Flags().String("path", bridge.DefaultConfigPath, "path to ori.yaml")

	cmd.AddCommand(validateCmd, showCmd)
	return cmd
}
