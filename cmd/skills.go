// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package cmd

import "github.com/spf13/cobra"

func newSkillsCommand(state *rootState) *cobra.Command {
	cmd := &cobra.Command{Use: "skills", Short: "Manage Ori skills"}
	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List installed runtime skills through the runtime bridge",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, args []string) error {
			return bridgeBacked(state, joinCommand("skills", "list"), args)
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "validate [path]",
		Short: "Validate a skill package through the runtime bridge",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return bridgeBacked(state, joinCommand("skills", "validate"), args)
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "reload",
		Short: "Ask the runtime to reload skills through the runtime bridge",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, args []string) error {
			return bridgeBacked(state, joinCommand("skills", "reload"), args)
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "install <name>",
		Short: "Install a skill from the Skills Hub",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, _ []string) error {
			return notImplemented("skills install requires live Skills Hub API")
		},
	})
	return cmd
}
