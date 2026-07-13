// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/ori-platform/ori-cli/internal/bridge"
)

// TestBridgeIntegrationConfigValidate runs the real runtime bridge against a
// fixture config when python3 and ori.cli_bridge are available. It skips
// cleanly when the runtime is not installed in the test environment.
func TestBridgeIntegrationConfigValidate(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	if err := probeBridgeModule(python); err != nil {
		t.Skipf("ori.cli_bridge not available: %v", err)
	}

	configPath := filepath.Join("testdata", "ori.yaml")
	fake := &realBridgeRunner{python: python}
	code, stdout, stderr := runWithOptions([]string{"config", "validate", configPath}, Options{Bridge: fake})
	if code != 0 {
		t.Fatalf("config validate failed: code=%d stderr=%q", code, stderr)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("bridge output is not valid JSON: %v\noutput: %s", err, stdout)
	}
	if payload["ok"] != true {
		t.Fatalf("unexpected bridge payload: %s", stdout)
	}
}

// TestBridgeIntegrationSkillsList runs the real runtime bridge skill listing
// against a fixture skills directory when available.
func TestBridgeIntegrationSkillsList(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	if err := probeBridgeModule(python); err != nil {
		t.Skipf("ori.cli_bridge not available: %v", err)
	}

	skillsDir := filepath.Join("testdata", "skills")
	fake := &realBridgeRunner{python: python}
	code, stdout, stderr := runWithOptions([]string{"skills", "list", "--skills-dir", skillsDir}, Options{Bridge: fake})
	if code != 0 {
		t.Fatalf("skills list failed: code=%d stderr=%q", code, stderr)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("bridge output is not valid JSON: %v\noutput: %s", err, stdout)
	}
	if payload["ok"] != true {
		t.Fatalf("unexpected bridge payload: %s", stdout)
	}
}

// realBridgeRunner invokes the actual Python bridge module for integration
// tests. It is not the production runner because it must tolerate the runtime
// not being installed.
type realBridgeRunner struct {
	python string
}

func (r *realBridgeRunner) Run(ctx context.Context, args ...string) (bridge.Result, error) {
	cmd := exec.CommandContext(ctx, r.python, append([]string{"-m", "ori.cli_bridge"}, args...)...)
	stdout, err := cmd.Output()
	var stderr []byte
	if exitErr := new(exec.ExitError); err != nil && errors.As(err, &exitErr) {
		stderr = exitErr.Stderr
	}
	return bridge.Result{Stdout: stdout, Stderr: stderr}, err
}

func probeBridgeModule(python string) error {
	cmd := exec.Command(python, "-c", "import ori.cli_bridge")
	return cmd.Run()
}
