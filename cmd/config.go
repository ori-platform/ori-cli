// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package cmd

import "github.com/spf13/cobra"

func newConfigCommand(state *rootState) *cobra.Command {
	cmd := &cobra.Command{Use: "config", Short: "Inspect and validate runtime configuration"}
	cmd.AddCommand(&cobra.Command{
		Use:   "validate [path]",
		Short: "Validate ori.yaml through the runtime bridge",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return bridgeBacked(state, joinCommand("config", "validate"), args)
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "show [path]",
		Short: "Show normalized runtime configuration through the runtime bridge",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return bridgeBacked(state, joinCommand("config", "show"), args)
		},
	})
	return cmd
}
