// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package cmd

import "github.com/spf13/cobra"

func newDeployCommand(_ *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "deploy",
		Short: "Provision a device deployment",
		RunE: func(_ *cobra.Command, _ []string) error {
			return notImplemented("deploy requires ori-cloud implementation and on-device keypair generation")
		},
	}
}
