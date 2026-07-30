// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package bridge

import (
	"context"
	"encoding/json"
	"fmt"
)

// CommandRunner runs runtime bridge commands. Runner satisfies it; tests may
// substitute fakes.
type CommandRunner interface {
	Run(ctx context.Context, args ...string) (Result, error)
}

// HealthSnapshot invokes the runtime bridge command
// `health snapshot --socket <path>` and returns the verbatim runtime health
// socket payload carried in the bridge result envelope. The runtime bridge
// is the contract source of truth for runtime-owned behavior; the CLI does
// not reimplement health semantics.
func HealthSnapshot(ctx context.Context, runner CommandRunner, socketPath string) ([]byte, error) {
	result, err := runner.Run(ctx, "health", "snapshot", "--socket", socketPath)
	if err != nil {
		return nil, fmt.Errorf("runtime bridge health snapshot failed: %w", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(result.Stdout, &payload); err != nil || payload == nil {
		return nil, fmt.Errorf("runtime bridge health snapshot returned invalid JSON")
	}
	if ok, _ := payload["ok"].(bool); !ok {
		code := "health_snapshot_failed"
		detail := "runtime bridge health snapshot returned ok=false"
		if errObj, ok := payload["error"].(map[string]any); ok {
			if c, ok := errObj["code"].(string); ok && c != "" {
				code = c
			}
			if d, ok := errObj["detail"].(string); ok && d != "" {
				detail = d
			}
		}
		return nil, fmt.Errorf("runtime bridge health snapshot error %s: %s", code, detail)
	}

	inner, present := payload["result"]
	if !present || inner == nil {
		return nil, fmt.Errorf("runtime bridge health snapshot is missing result payload")
	}
	raw, err := json.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("runtime bridge health snapshot result is not encodable: %w", err)
	}
	return raw, nil
}
