// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/ori-platform/ori-cli/internal/bridge"
	"github.com/ori-platform/ori-cli/internal/rpc"
	"github.com/ori-platform/ori-cli/internal/token"
)

type fakeBridge struct {
	args [][]string
	err  error
	out  []byte
}

func (f *fakeBridge) Run(_ context.Context, args ...string) (bridge.Result, error) {
	copied := append([]string(nil), args...)
	f.args = append(f.args, copied)
	return bridge.Result{Stdout: f.out}, f.err
}

func runWithOptions(args []string, opts Options) (int, string, string) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := ExecuteWithOptions(args, &stdout, &stderr, opts)
	return code, stdout.String(), stderr.String()
}

func TestHelp(t *testing.T) {
	code, stdout, stderr := runWithOptions([]string{"help"}, Options{})
	if code != 0 {
		t.Fatalf("expected 0, got %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, "operator CLI") {
		t.Fatalf("unexpected help: %s", stdout)
	}
}

func TestUnknownCommandFails(t *testing.T) {
	code, _, stderr := runWithOptions([]string{"unknown"}, Options{})
	if code == 0 || !strings.Contains(stderr, "Error: unknown command") {
		t.Fatalf("expected unknown command failure, got code=%d stderr=%q", code, stderr)
	}
}

func TestJSONErrorPayload(t *testing.T) {
	fake := &fakeBridge{err: errors.New("missing bridge")}
	code, _, stderr := runWithOptions([]string{"--output", "json", "config", "validate"}, Options{Bridge: fake})
	if code == 0 || !strings.Contains(stderr, `"error"`) {
		t.Fatalf("expected json error payload, got code=%d stderr=%q", code, stderr)
	}
}

func TestConfigValidateCallsRuntimeBridge(t *testing.T) {
	fake := &fakeBridge{out: []byte("ok\n")}
	code, stdout, stderr := runWithOptions([]string{"config", "validate", "ori.yaml"}, Options{Bridge: fake})
	if code != 0 {
		t.Fatalf("expected success, got code=%d stderr=%q", code, stderr)
	}
	if stdout != "ok\n" {
		t.Fatalf("stdout = %q", stdout)
	}
	want := [][]string{{"config-validate", "ori.yaml"}}
	if !reflect.DeepEqual(fake.args, want) {
		t.Fatalf("bridge args = %#v, want %#v", fake.args, want)
	}
}

func TestSkillsListCallsRuntimeBridge(t *testing.T) {
	fake := &fakeBridge{out: []byte("[]\n")}
	code, _, stderr := runWithOptions([]string{"skills", "list"}, Options{Bridge: fake})
	if code != 0 {
		t.Fatalf("expected success, got code=%d stderr=%q", code, stderr)
	}
	want := [][]string{{"skills-list"}}
	if !reflect.DeepEqual(fake.args, want) {
		t.Fatalf("bridge args = %#v, want %#v", fake.args, want)
	}
}

func TestPersistentOutputFlagWorksAfterSubcommand(t *testing.T) {
	getHealth := func(context.Context, string) (rpc.RuntimeHealthStatus, error) {
		return rpc.RuntimeHealthStatus{Status: "ok", Raw: map[string]any{"status": "ok"}}, nil
	}
	code, stdout, stderr := runWithOptions([]string{"doctor", "runtime-health", "--output", "json"}, Options{GetHealth: getHealth})
	if code != 0 {
		t.Fatalf("expected success, got code=%d stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, `"status": "ok"`) {
		t.Fatalf("unexpected stdout: %s", stdout)
	}
}

func TestRuntimeHealthJSONUsesParsedHealthStatus(t *testing.T) {
	getHealth := func(context.Context, string) (rpc.RuntimeHealthStatus, error) {
		return rpc.RuntimeHealthStatus{Status: "ok", DeviceID: "edge-1", Raw: map[string]any{"status": "ok", "device_id": "edge-1"}}, nil
	}
	code, stdout, stderr := runWithOptions([]string{"--json", "doctor", "runtime-health"}, Options{GetHealth: getHealth})
	if code != 0 {
		t.Fatalf("expected success, got code=%d stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, `"device_id": "edge-1"`) {
		t.Fatalf("unexpected stdout: %s", stdout)
	}
}

func TestTokenUseIsOfflineCommand(t *testing.T) {
	called := false
	useToken := func(raw string) (token.OfflineUseResult, error) {
		called = true
		return token.UseOffline(raw)
	}
	code, stdout, stderr := runWithOptions([]string{"token", "use", "abc"}, Options{UseToken: useToken})
	if code != 0 {
		t.Fatalf("expected token use success, got %d: %s", code, stderr)
	}
	if !called {
		t.Fatal("token use hook was not called")
	}
	if !strings.Contains(stdout, "offline token accepted") {
		t.Fatalf("unexpected output: %s", stdout)
	}
}

func TestTokenGenerateExplicitlyRequiresCloud(t *testing.T) {
	code, _, stderr := runWithOptions([]string{"token", "generate"}, Options{})
	if code == 0 || !strings.Contains(stderr, "ori-cloud") {
		t.Fatalf("expected cloud requirement, got code=%d stderr=%q", code, stderr)
	}
}
