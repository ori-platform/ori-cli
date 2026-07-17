// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func newStateCommand(state *rootState) *cobra.Command {
	cmd := &cobra.Command{Use: "state", Short: "Inspect local runtime state"}

	actionLogCmd := &cobra.Command{
		Use:   "action-log",
		Short: "Read the runtime action log through the runtime bridge",
		Long: `Read the runtime action_log table through the runtime bridge.

The runtime owns the state schema and access rules; the CLI never opens
SQLite directly.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			limit, err := cmd.Flags().GetInt("limit")
			if err != nil {
				return fmt.Errorf("failed to read --limit: %w", err)
			}
			filters := buildStateFilters(limit)
			return runStateQuery(state, "action-log", filters)
		},
	}
	actionLogCmd.Flags().Int("limit", 0, "maximum number of rows to return")

	historyCmd := &cobra.Command{
		Use:   "history",
		Short: "Read runtime sensor history through the runtime bridge",
		Long: `Read the runtime sensor_history table through the runtime bridge.

The runtime owns the state schema and access rules; the CLI never opens
SQLite directly.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			sensorID, err := cmd.Flags().GetString("sensor-id")
			if err != nil {
				return fmt.Errorf("failed to read --sensor-id: %w", err)
			}
			limit, err := cmd.Flags().GetInt("limit")
			if err != nil {
				return fmt.Errorf("failed to read --limit: %w", err)
			}
			filters := buildStateFilters(limit, "sensor_id="+sensorID)
			return runStateQuery(state, "history", filters)
		},
	}
	historyCmd.Flags().String("sensor-id", "", "filter to a specific sensor_id (required)")
	historyCmd.Flags().Int("limit", 0, "maximum number of rows to return")
	_ = historyCmd.MarkFlagRequired("sensor-id")

	cmd.AddCommand(actionLogCmd, historyCmd)
	return cmd
}

func buildStateFilters(limit int, filters ...string) []string {
	if limit > 0 {
		filters = append(filters, fmt.Sprintf("limit=%d", limit))
	}
	return filters
}

func runStateQuery(state *rootState, subcommand string, filters []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	bridgeArgs := append([]string{"state", subcommand}, filters...)
	result, err := state.bridge.Run(ctx, bridgeArgs...)
	if err != nil {
		if len(result.Stderr) > 0 {
			_, _ = state.stderr.Write(result.Stderr)
		}
		return fmt.Errorf("runtime bridge command %v failed: %w", bridgeArgs, err)
	}

	var payload map[string]any
	if jsonErr := json.Unmarshal(result.Stdout, &payload); jsonErr != nil {
		if len(result.Stderr) > 0 {
			_, _ = state.stderr.Write(result.Stderr)
		}
		return fmt.Errorf("runtime bridge returned invalid JSON: %w", jsonErr)
	}
	if payload == nil {
		return fmt.Errorf("runtime bridge returned a non-object JSON value")
	}
	ok, _ := payload["ok"].(bool)

	if !ok {
		// The bridge reported a structured error. Render it and return a
		// non-zero exit code so callers can distinguish failure from an empty
		// successful query.
		if state.json {
			_, _ = state.stdout.Write(result.Stdout)
		} else {
			_ = renderStateQueryText(state.stdout, payload)
		}
		return fmt.Errorf("state %s failed: %s", subcommand, errorDetail(payload))
	}

	if state.json {
		_, err = state.stdout.Write(result.Stdout)
		return err
	}

	return renderStateQueryText(state.stdout, payload)
}

func errorDetail(payload map[string]any) string {
	errObj, _ := payload["error"].(map[string]any)
	if errObj == nil {
		return "unknown error"
	}
	code, _ := errObj["code"].(string)
	detail, _ := errObj["detail"].(string)
	if code != "" && detail != "" {
		return fmt.Sprintf("%s: %s", code, detail)
	}
	if detail != "" {
		return detail
	}
	if code != "" {
		return code
	}
	return "unknown error"
}

func renderStateQueryText(w io.Writer, payload map[string]any) error {
	if ok, _ := payload["ok"].(bool); !ok {
		// Error payloads are rendered as compact JSON so the detail is preserved.
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(payload)
	}

	result, ok := payload["result"].([]any)
	if !ok {
		// The bridge returned an ok payload with an unexpected result shape.
		// Emit compact JSON rather than losing typed values.
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(payload)
	}

	if len(result) == 0 {
		fmt.Fprintln(w, "No rows returned.")
		return nil
	}

	for i, row := range result {
		fmt.Fprintf(w, "--- row %d ---\n", i)
		renderStateRow(w, "", row)
	}
	return nil
}

func renderStateRow(w io.Writer, prefix string, value any) {
	switch v := value.(type) {
	case map[string]any:
		for _, k := range sortedKeys(v) {
			child := v[k]
			if isScalar(child) {
				fmt.Fprintf(w, "%s%s: %v\n", prefix, k, child)
			} else {
				fmt.Fprintf(w, "%s%s:\n", prefix, k)
				renderStateRow(w, prefix+"  ", child)
			}
		}
	case []any:
		for i, item := range v {
			if isScalar(item) {
				fmt.Fprintf(w, "%s[%d]: %v\n", prefix, i, item)
			} else {
				fmt.Fprintf(w, "%s[%d]:\n", prefix, i)
				renderStateRow(w, prefix+"  ", item)
			}
		}
	default:
		fmt.Fprintf(w, "%s%v\n", prefix, v)
	}
}

func isScalar(value any) bool {
	switch value.(type) {
	case string, bool, int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64,
		float32, float64, nil:
		return true
	default:
		return false
	}
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	for i := 0; i < len(keys)-1; i++ {
		for j := i + 1; j < len(keys); j++ {
			if strings.Compare(keys[i], keys[j]) > 0 {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	return keys
}
