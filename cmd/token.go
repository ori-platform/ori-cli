// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"

	"github.com/ori-platform/ori-cli/internal/output"
	"github.com/spf13/cobra"
)

func newTokenCommand(state *rootState) *cobra.Command {
	cmd := &cobra.Command{Use: "token", Short: "Manage Ori offline tokens"}
	cmd.AddCommand(&cobra.Command{
		Use:   "use <token>",
		Short: "Present an offline token to the local runtime without cloud access",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			result, err := state.useToken(args[0])
			if err != nil {
				return err
			}
			if state.json {
				return output.JSON(state.stdout, result)
			}
			fmt.Fprintln(state.stdout, "offline token accepted for local runtime presentation")
			return nil
		},
	})
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
