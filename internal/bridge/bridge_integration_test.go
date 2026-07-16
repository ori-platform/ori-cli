// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package bridge

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeFakePython writes a script to a temporary file, makes it executable, and
// returns its path. The script body is executed by python3.
func writeFakePython(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "fake.py")
	if err := os.WriteFile(script, []byte("#!/usr/bin/env python3\n"+body), 0o755); err != nil {
		t.Fatalf("write fake python: %v", err)
	}
	return script
}

func TestBridgeRunnerInvokesPythonModule(t *testing.T) {
	script := writeFakePython(t, `
import sys
import json
print(json.dumps({"ok": True, "args": sys.argv[1:]}))
`)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	runner := Runner{Python: script, Module: "ori.cli_bridge"}
	result, err := runner.Run(ctx, "config", "validate", "--path", "ori.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(result.Stdout, &payload); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\noutput: %s", err, result.Stdout)
	}

	args, ok := payload["args"].([]any)
	if !ok {
		t.Fatalf("expected args array, got %#v", payload["args"])
	}
	want := []string{"-m", "ori.cli_bridge", "config", "validate", "--path", "ori.yaml"}
	if len(args) != len(want) {
		t.Fatalf("args length mismatch: got %v, want %v", args, want)
	}
	for i, v := range want {
		if args[i] != v {
			t.Fatalf("arg[%d] = %q, want %q", i, args[i], v)
		}
	}
}

func TestBridgeRunnerSupportsLegacyAliases(t *testing.T) {
	script := writeFakePython(t, `
import sys
import json
print(json.dumps({"ok": True, "args": sys.argv[1:]}))
`)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	runner := Runner{Python: script, Module: "ori.cli_bridge"}
	result, err := runner.Run(ctx, "config-validate", "--path", "ori.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(result.Stdout, &payload); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\noutput: %s", err, result.Stdout)
	}
	args := payload["args"].([]any)
	if len(args) < 3 || args[2] != "config-validate" {
		t.Fatalf("legacy alias not passed through: %v", args)
	}
}

func TestBridgeRunnerParsesError(t *testing.T) {
	script := writeFakePython(t, `
import sys
import json
sys.stderr.write("missing required field: action\n")
print(json.dumps({"ok": False, "error": "missing required field: action"}))
sys.exit(1)
`)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	runner := Runner{Python: script, Module: "ori.cli_bridge"}
	result, err := runner.Run(ctx, "skills", "list")
	if err == nil {
		t.Fatal("expected bridge failure")
	}
	if !strings.Contains(err.Error(), "bridge failed") {
		t.Fatalf("expected wrapped bridge failure, got: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(result.Stdout, &payload); err != nil {
		t.Fatalf("error stdout is not valid JSON: %v\noutput: %s", err, result.Stdout)
	}
	if payload["ok"] != false {
		t.Fatalf("expected ok=false, got %v", payload)
	}
	if !strings.Contains(string(result.Stderr), "missing required field") {
		t.Fatalf("expected stderr diagnostics, got: %q", result.Stderr)
	}
}

func TestBridgeRunnerKeepsStdoutAndStderrSeparate(t *testing.T) {
	script := writeFakePython(t, `
import sys
import json
sys.stdout.write('{"ok":true}\n')
sys.stderr.write('diagnostic line\n')
`)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	runner := Runner{Python: script, Module: "ori.cli_bridge"}
	result, err := runner.Run(ctx, "config", "show")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.TrimSpace(string(result.Stdout)) != `{"ok":true}` {
		t.Fatalf("unexpected stdout: %q", result.Stdout)
	}
	if strings.TrimSpace(string(result.Stderr)) != "diagnostic line" {
		t.Fatalf("unexpected stderr: %q", result.Stderr)
	}
}

func TestBridgeRunnerPreservesArgumentQuoting(t *testing.T) {
	script := writeFakePython(t, `
import sys
import json
print(json.dumps({"ok": True, "args": sys.argv[3:]}))
`)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	runner := Runner{Python: script, Module: "ori.cli_bridge"}
	result, err := runner.Run(ctx, "config", "validate", "--path", "path with spaces.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(result.Stdout, &payload); err != nil {
		t.Fatalf("stdout is not valid JSON: %v", err)
	}
	args := payload["args"].([]any)
	if len(args) != 4 || args[0] != "config" || args[1] != "validate" || args[2] != "--path" || args[3] != "path with spaces.yaml" {
		t.Fatalf("quoted argument was split or reordered: %v", args)
	}
}

func TestBridgeRunnerContextCancellationTerminatesSubprocess(t *testing.T) {
	script := writeFakePython(t, `
import sys
import time
try:
    time.sleep(10)
except KeyboardInterrupt:
    pass
print(json.dumps({"ok": True}))
`)

	ctx, cancel := context.WithCancel(context.Background())
	runner := Runner{Python: script, Module: "ori.cli_bridge"}

	// Start a goroutine to cancel shortly after the subprocess begins.
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, err := runner.Run(ctx, "slow", "command")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected cancellation error")
	}
	if elapsed > 3*time.Second {
		t.Fatalf("subprocess was not terminated promptly: %v", elapsed)
	}
}

func TestBridgeRunnerMalformedStdoutCaptured(t *testing.T) {
	script := writeFakePython(t, `
print("this is not json")
`)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	runner := Runner{Python: script, Module: "ori.cli_bridge"}
	result, err := runner.Run(ctx, "config", "validate")
	if err != nil {
		t.Fatalf("unexpected error for exit-zero malformed output: %v", err)
	}
	if strings.TrimSpace(string(result.Stdout)) != "this is not json" {
		t.Fatalf("unexpected stdout: %q", result.Stdout)
	}
}

func TestDefaultRunnerUsesPython3AndOriCliBridge(t *testing.T) {
	r := DefaultRunner()
	if r.Python != "python3" {
		t.Errorf("Python = %q, want python3", r.Python)
	}
	if r.Module != "ori.cli_bridge" {
		t.Errorf("Module = %q, want ori.cli_bridge", r.Module)
	}
}

func TestRunnerFallsBackToDefaultsWhenFieldsEmpty(t *testing.T) {
	script := writeFakePython(t, fmt.Sprintf(`
import sys
import json
print(json.dumps({"ok": True, "module_arg": sys.argv[1], "cmd_arg": sys.argv[2]}))
`))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	runner := Runner{Python: script} // Module left empty
	result, err := runner.Run(ctx, "config", "validate")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(result.Stdout, &payload); err != nil {
		t.Fatalf("stdout is not valid JSON: %v", err)
	}
	if payload["module_arg"] != "-m" {
		t.Fatalf("expected -m flag, got %v", payload)
	}
	if payload["cmd_arg"] != "ori.cli_bridge" {
		t.Fatalf("expected default module, got %v", payload)
	}
}
