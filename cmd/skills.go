// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"

	"github.com/ori-platform/ori-cli/internal/bridge"
	"github.com/ori-platform/ori-cli/internal/runtime"
	"github.com/spf13/cobra"
)

func newSkillsCommand(state *rootState) *cobra.Command {
	cmd := &cobra.Command{Use: "skills", Short: "Manage Ori skills"}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List installed runtime skills through the runtime bridge",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir, err := cmd.Flags().GetString("skills-dir")
			if err != nil {
				return fmt.Errorf("failed to read --skills-dir: %w", err)
			}
			bridgeArgs := []string{"skills", "list", "--skills-dir", dir}
			requireSigned, err := cmd.Flags().GetBool("require-signed")
			if err != nil {
				return fmt.Errorf("failed to read --require-signed: %w", err)
			}
			if requireSigned {
				bridgeArgs = append(bridgeArgs, "--require-signed")
			}
			return bridgeBacked(state, bridgeArgs...)
		},
	}
	listCmd.Flags().String("skills-dir", bridge.DefaultSkillsDir, "skills directory")
	listCmd.Flags().Bool("require-signed", false, "only list skills with valid signatures")

	validateCmd := &cobra.Command{
		Use:   "validate [path]",
		Short: "Validate a skill package through the runtime bridge",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := cmd.Flags().GetString("skills-dir")
			if err != nil {
				return fmt.Errorf("failed to read --skills-dir: %w", err)
			}
			if len(args) > 0 {
				dir = args[0]
			}
			bridgeArgs := []string{"skills", "validate", "--skills-dir", dir}
			requireSigned, err := cmd.Flags().GetBool("require-signed")
			if err != nil {
				return fmt.Errorf("failed to read --require-signed: %w", err)
			}
			if requireSigned {
				bridgeArgs = append(bridgeArgs, "--require-signed")
			}
			return bridgeBacked(state, bridgeArgs...)
		},
	}
	validateCmd.Flags().String("skills-dir", bridge.DefaultSkillsDir, "skills directory")
	validateCmd.Flags().Bool("require-signed", false, "require a valid signature on the skill")

	reloadCmd := &cobra.Command{
		Use:   "reload --pid <pid>",
		Short: "Ask a running runtime process to reload skills via SIGHUP",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			pid, err := cmd.Flags().GetInt("pid")
			if err != nil || pid <= 0 {
				return fmt.Errorf("--pid must be a positive process ID")
			}
			if err := runtime.ReloadSkills(pid); err != nil {
				return fmt.Errorf("skills reload failed: %w", err)
			}
			fmt.Fprintln(state.stdout, "skills reload signal sent")
			return nil
		},
	}
	reloadCmd.Flags().Int("pid", 0, "runtime process ID to signal")

	cmd.AddCommand(listCmd, validateCmd, reloadCmd)
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
