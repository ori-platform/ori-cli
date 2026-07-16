// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/ori-platform/ori-cli/internal/bridge"
	"github.com/ori-platform/ori-cli/internal/output"
	"github.com/ori-platform/ori-cli/internal/rpc"
	"github.com/ori-platform/ori-cli/internal/token"
	"github.com/spf13/cobra"
)

type BridgeRunner interface {
	Run(ctx context.Context, args ...string) (bridge.Result, error)
}

type Options struct {
	Bridge    BridgeRunner
	GetHealth func(context.Context, string) (rpc.RuntimeHealthStatus, error)
	UseToken  func(string) (token.OfflineUseResult, error)
}

type rootState struct {
	json      bool
	stdout    io.Writer
	stderr    io.Writer
	bridge    BridgeRunner
	getHealth func(context.Context, string) (rpc.RuntimeHealthStatus, error)
	useToken  func(string) (token.OfflineUseResult, error)
}

func Execute(args []string, stdout io.Writer, stderr io.Writer) int {
	return ExecuteWithOptions(args, stdout, stderr, Options{})
}

func ExecuteWithOptions(args []string, stdout io.Writer, stderr io.Writer, opts Options) int {
	maybeShowFirstRunWelcome(args, stdout, stderr)

	state := rootState{
		stdout:    stdout,
		stderr:    stderr,
		bridge:    opts.Bridge,
		getHealth: opts.GetHealth,
		useToken:  opts.UseToken,
	}
	if state.bridge == nil {
		state.bridge = bridge.DefaultRunner()
	}
	if state.getHealth == nil {
		state.getHealth = rpc.GetHealth
	}
	if state.useToken == nil {
		state.useToken = token.UseOffline
	}

	root := newRootCommand(&state)
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)
	if err := root.Execute(); err != nil {
		output.Error(stderr, state.json, err.Error())
		return 1
	}
	return 0
}

func newRootCommand(state *rootState) *cobra.Command {
	root := &cobra.Command{
		Use:           "ori",
		Short:         "operator CLI for Ori runtime",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().BoolVar(&state.json, "json", false, "emit JSON output")
	root.PersistentFlags().String("output", "text", "output format: text or json")
	root.PersistentPreRunE = func(cmd *cobra.Command, _ []string) error {
		format, err := cmd.Flags().GetString("output")
		if err != nil {
			return err
		}
		switch format {
		case "json":
			state.json = true
		case "text":
		case "":
		default:
			return fmt.Errorf("unsupported output format %q", format)
		}
		return nil
	}
	installHelpTemplate(state, root)

	root.AddCommand(newDoctorCommand(state))
	root.AddCommand(newConfigCommand(state))
	root.AddCommand(newSkillsCommand(state))
	root.AddCommand(newTokenCommand(state))
	root.AddCommand(newStateCommand(state))
	root.AddCommand(newDeployCommand(state))
	return root
}

func bridgeBacked(state *rootState, bridgeArgs ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := state.bridge.Run(ctx, bridgeArgs...)
	if err != nil {
		if len(result.Stderr) > 0 {
			_, _ = state.stderr.Write(result.Stderr)
		}
		return fmt.Errorf("runtime bridge command %v failed: %w", bridgeArgs, err)
	}
	// The runtime bridge contract requires exactly one JSON object on stdout.
	// Reject malformed output before it reaches the operator.
	var payload any
	if jsonErr := json.Unmarshal(result.Stdout, &payload); jsonErr != nil {
		if len(result.Stderr) > 0 {
			_, _ = state.stderr.Write(result.Stderr)
		}
		return fmt.Errorf("runtime bridge returned invalid JSON: %w", jsonErr)
	}
	if len(result.Stdout) > 0 {
		_, _ = state.stdout.Write(result.Stdout)
	}
	return nil
}

func notImplemented(message string) error {
	return errors.New("not yet implemented: " + message)
}
