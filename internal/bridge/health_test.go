// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type fakeCommandRunner struct {
	result Result
	err    error
	args   []string
}

func (f *fakeCommandRunner) Run(_ context.Context, args ...string) (Result, error) {
	f.args = args
	return f.result, f.err
}

func TestHealthSnapshotUnwrapsBridgeEnvelope(t *testing.T) {
	inner := `{"schema_version":1,"ok":true,"health":{"device_id":"edge-1"}}`
	runner := &fakeCommandRunner{
		result: Result{Stdout: []byte(`{"schema_version":1,"ok":true,"command":"health snapshot","result":` + inner + `}` + "\n")},
	}
	raw, err := HealthSnapshot(context.Background(), runner, "/tmp/health.sock")
	if err != nil {
		t.Fatalf("HealthSnapshot: %v", err)
	}
	var unwrapped map[string]any
	if err := json.Unmarshal(raw, &unwrapped); err != nil {
		t.Fatalf("unwrapped payload is not valid JSON: %v", err)
	}
	health, _ := unwrapped["health"].(map[string]any)
	if health["device_id"] != "edge-1" {
		t.Fatalf("unwrapped payload = %s", raw)
	}
	wantArgs := []string{"health", "snapshot", "--socket", "/tmp/health.sock"}
	if strings.Join(runner.args, " ") != strings.Join(wantArgs, " ") {
		t.Fatalf("args = %v, want %v", runner.args, wantArgs)
	}
}

func TestHealthSnapshotPropagatesBridgeError(t *testing.T) {
	runner := &fakeCommandRunner{err: errors.New("exit status 2")}
	_, err := HealthSnapshot(context.Background(), runner, "/tmp/health.sock")
	if err == nil || !strings.Contains(err.Error(), "health snapshot failed") {
		t.Fatalf("expected bridge failure error, got %v", err)
	}
}

func TestHealthSnapshotRejectsInvalidJSON(t *testing.T) {
	runner := &fakeCommandRunner{result: Result{Stdout: []byte("not-json\n")}}
	_, err := HealthSnapshot(context.Background(), runner, "/tmp/health.sock")
	if err == nil || !strings.Contains(err.Error(), "invalid JSON") {
		t.Fatalf("expected invalid JSON error, got %v", err)
	}
}

func TestHealthSnapshotRejectsOkFalse(t *testing.T) {
	payload := `{"schema_version":1,"ok":false,"command":"health snapshot","error":{"code":"health_socket_unavailable","detail":"dial failed"}}`
	runner := &fakeCommandRunner{result: Result{Stdout: []byte(payload + "\n")}}
	_, err := HealthSnapshot(context.Background(), runner, "/tmp/health.sock")
	if err == nil {
		t.Fatal("expected error for ok=false bridge response")
	}
	if !strings.Contains(err.Error(), "health_socket_unavailable") || !strings.Contains(err.Error(), "dial failed") {
		t.Fatalf("expected structured bridge error, got %v", err)
	}
}

func TestHealthSnapshotRejectsMissingResult(t *testing.T) {
	runner := &fakeCommandRunner{result: Result{Stdout: []byte(`{"schema_version":1,"ok":true,"command":"health snapshot"}` + "\n")}}
	_, err := HealthSnapshot(context.Background(), runner, "/tmp/health.sock")
	if err == nil || !strings.Contains(err.Error(), "missing result") {
		t.Fatalf("expected missing result error, got %v", err)
	}
}
