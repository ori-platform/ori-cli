// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package cmd

import "github.com/spf13/cobra"

func newStateCommand(_ *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "state",
		Short: "Inspect local runtime state",
		RunE: func(_ *cobra.Command, _ []string) error {
			return notImplemented("state commands require SQLite implementation")
		},
	}
}
