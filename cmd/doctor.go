// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/ori-platform/ori-cli/internal/output"
	"github.com/ori-platform/ori-cli/internal/rpc"
	"github.com/spf13/cobra"
)

func newDoctorCommand(state *rootState) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Inspect local Ori runtime health",
		RunE: func(_ *cobra.Command, _ []string) error {
			if state.json {
				return output.JSON(state.stdout, map[string]any{"ok": true, "command": "doctor", "status": "bootstrap"})
			}
			fmt.Fprintln(state.stdout, "ori doctor: bootstrap checks not yet wired; use 'ori doctor runtime-health'")
			return nil
		},
	}
	cmd.AddCommand(newRuntimeHealthCommand(state))
	return cmd
}

func newRuntimeHealthCommand(state *rootState) *cobra.Command {
	socketPath := rpc.DefaultHealthSocket
	cmd := &cobra.Command{
		Use:   "runtime-health",
		Short: "Read runtime health from the local Unix socket",
		RunE: func(_ *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			status, err := state.getHealth(ctx, socketPath)
			if err != nil {
				return fmt.Errorf("runtime health unavailable: %w", err)
			}
			if state.json {
				return output.JSON(state.stdout, status)
			}
			fmt.Fprintf(state.stdout, "Runtime health: %s\n", status.StatusOrUnknown())
			if status.DeviceID != "" {
				fmt.Fprintf(state.stdout, "Device: %s\n", status.DeviceID)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&socketPath, "socket", rpc.DefaultHealthSocket, "runtime health Unix socket path")
	return cmd
}
