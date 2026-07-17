// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ori-platform/ori-cli/internal/bridge"
)

type recordingBridge struct {
	calls [][]string
	out   []byte
	err   error
}

func (r *recordingBridge) Run(_ context.Context, args ...string) (bridge.Result, error) {
	copied := append([]string(nil), args...)
	r.calls = append(r.calls, copied)
	return bridge.Result{Stdout: r.out}, r.err
}

func TestStateActionLogDelegatesToBridge(t *testing.T) {
	fake := &recordingBridge{
		out: []byte(`{"ok":true,"schema_version":1,"command":"state action-log","result":[{"id":1,"action_name":"trip_relay"}]}` + "\n"),
	}
	code, stdout, stderr := runWithOptions([]string{"state", "action-log", "--limit", "10"}, Options{Bridge: fake})
	if code != 0 {
		t.Fatalf("expected success, got code=%d stderr=%q", code, stderr)
	}
	if len(fake.calls) != 1 {
		t.Fatalf("expected 1 bridge call, got %d", len(fake.calls))
	}
	want := []string{"state", "action-log", "limit=10"}
	if len(fake.calls[0]) != len(want) {
		t.Fatalf("bridge args = %v, want %v", fake.calls[0], want)
	}
	for i, arg := range want {
		if fake.calls[0][i] != arg {
			t.Fatalf("bridge arg[%d] = %q, want %q", i, fake.calls[0][i], arg)
		}
	}
	if !strings.Contains(stdout, "trip_relay") {
		t.Fatalf("expected trip_relay in stdout, got %q", stdout)
	}
}

func TestStateActionLogDefaultNoLimit(t *testing.T) {
	fake := &recordingBridge{
		out: []byte(`{"ok":true,"schema_version":1,"command":"state action-log","result":[]}` + "\n"),
	}
	code, _, stderr := runWithOptions([]string{"state", "action-log"}, Options{Bridge: fake})
	if code != 0 {
		t.Fatalf("expected success, got code=%d stderr=%q", code, stderr)
	}
	want := []string{"state", "action-log"}
	if len(fake.calls[0]) != len(want) {
		t.Fatalf("bridge args = %v, want %v", fake.calls[0], want)
	}
}

func TestStateHistoryRequiresSensorID(t *testing.T) {
	code, _, stderr := runWithOptions([]string{"state", "history"}, Options{})
	if code == 0 {
		t.Fatalf("expected failure without --sensor-id")
	}
	if !strings.Contains(stderr, "sensor-id") {
		t.Fatalf("expected --sensor-id error, got stderr=%q", stderr)
	}
}

func TestStateHistoryDelegatesToBridge(t *testing.T) {
	fake := &recordingBridge{
		out: []byte(`{"ok":true,"schema_version":1,"command":"state history","result":[{"id":1,"sensor_id":"pir_01","value":1}]}` + "\n"),
	}
	code, stdout, stderr := runWithOptions([]string{"state", "history", "--sensor-id", "pir_01", "--limit", "100"}, Options{Bridge: fake})
	if code != 0 {
		t.Fatalf("expected success, got code=%d stderr=%q", code, stderr)
	}
	if len(fake.calls) != 1 {
		t.Fatalf("expected 1 bridge call, got %d", len(fake.calls))
	}
	want := []string{"state", "history", "sensor_id=pir_01", "limit=100"}
	if len(fake.calls[0]) != len(want) {
		t.Fatalf("bridge args = %v, want %v", fake.calls[0], want)
	}
	for i, arg := range want {
		if fake.calls[0][i] != arg {
			t.Fatalf("bridge arg[%d] = %q, want %q", i, fake.calls[0][i], arg)
		}
	}
	if !strings.Contains(stdout, "pir_01") {
		t.Fatalf("expected pir_01 in stdout, got %q", stdout)
	}
}

func TestStateHistoryDefaultNoLimit(t *testing.T) {
	fake := &recordingBridge{
		out: []byte(`{"ok":true,"schema_version":1,"command":"state history","result":[]}` + "\n"),
	}
	code, _, stderr := runWithOptions([]string{"state", "history", "--sensor-id", "pir_01"}, Options{Bridge: fake})
	if code != 0 {
		t.Fatalf("expected success, got code=%d stderr=%q", code, stderr)
	}
	want := []string{"state", "history", "sensor_id=pir_01"}
	if len(fake.calls[0]) != len(want) {
		t.Fatalf("bridge args = %v, want %v", fake.calls[0], want)
	}
}

func TestStateActionLogJSONPreservesTypes(t *testing.T) {
	fake := &recordingBridge{
		out: []byte(`{"ok":true,"schema_version":1,"command":"state action-log","result":[{"id":1,"executed":true,"tier":"B"}]}` + "\n"),
	}
	code, stdout, stderr := runWithOptions([]string{"--json", "state", "action-log"}, Options{Bridge: fake})
	if code != 0 {
		t.Fatalf("expected success, got code=%d stderr=%q", code, stderr)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\noutput: %s", err, stdout)
	}
	result := payload["result"].([]any)
	row := result[0].(map[string]any)
	if row["id"] != float64(1) {
		t.Fatalf("expected numeric id, got %T %v", row["id"], row["id"])
	}
	if row["executed"] != true {
		t.Fatalf("expected boolean executed, got %T %v", row["executed"], row["executed"])
	}
	if row["tier"] != "B" {
		t.Fatalf("expected string tier, got %T %v", row["tier"], row["tier"])
	}
}

func TestStateHistoryJSONPreservesTypes(t *testing.T) {
	fake := &recordingBridge{
		out: []byte(`{"ok":true,"schema_version":1,"command":"state history","result":[{"id":1,"value":0.85,"quality":1}]}` + "\n"),
	}
	code, stdout, stderr := runWithOptions([]string{"state", "history", "--sensor-id", "pir_01", "--json"}, Options{Bridge: fake})
	if code != 0 {
		t.Fatalf("expected success, got code=%d stderr=%q", code, stderr)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\noutput: %s", err, stdout)
	}
	result := payload["result"].([]any)
	row := result[0].(map[string]any)
	if row["value"] != 0.85 {
		t.Fatalf("expected float value, got %T %v", row["value"], row["value"])
	}
	if row["quality"] != float64(1) {
		t.Fatalf("expected numeric quality, got %T %v", row["quality"], row["quality"])
	}
}

func TestStateHistoryTextOutput(t *testing.T) {
	fake := &recordingBridge{
		out: []byte(`{"ok":true,"schema_version":1,"command":"state history","result":[{"id":1,"sensor_id":"pir_01","nested":{"zone":"front"}}]}` + "\n"),
	}
	code, stdout, stderr := runWithOptions([]string{"state", "history", "--sensor-id", "pir_01"}, Options{Bridge: fake})
	if code != 0 {
		t.Fatalf("expected success, got code=%d stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, "sensor_id: pir_01") {
		t.Fatalf("expected formatted sensor_id, got %q", stdout)
	}
	if !strings.Contains(stdout, "zone: front") {
		t.Fatalf("expected formatted nested value, got %q", stdout)
	}
}

func TestStateActionLogEmptyResult(t *testing.T) {
	fake := &recordingBridge{
		out: []byte(`{"ok":true,"schema_version":1,"command":"state action-log","result":[]}` + "\n"),
	}
	code, stdout, _ := runWithOptions([]string{"state", "action-log"}, Options{Bridge: fake})
	if code != 0 {
		t.Fatalf("expected success, got code=%d", code)
	}
	if !strings.Contains(stdout, "No rows returned") {
		t.Fatalf("expected empty result message, got %q", stdout)
	}
}

func TestStateHistoryBridgeError(t *testing.T) {
	fake := &recordingBridge{
		out: []byte(`{"ok":false,"schema_version":1,"command":"state history","error":{"code":"invalid_filter","detail":"unknown sensor_id"}}` + "\n"),
	}
	code, stdout, _ := runWithOptions([]string{"state", "history", "--sensor-id", "unknown"}, Options{Bridge: fake})
	if code == 0 {
		t.Fatalf("expected failure for bridge error")
	}
	if !strings.Contains(stdout, "invalid_filter") {
		t.Fatalf("expected error code in output, got %q", stdout)
	}
}

func TestStateActionLogBridgeUnavailable(t *testing.T) {
	fake := &recordingBridge{err: errors.New("exec: python3 not found")}
	code, _, stderr := runWithOptions([]string{"state", "action-log"}, Options{Bridge: fake})
	if code == 0 {
		t.Fatalf("expected failure when bridge unavailable")
	}
	if !strings.Contains(stderr, "runtime bridge command") {
		t.Fatalf("expected bridge failure message, got stderr=%q", stderr)
	}
}

func TestStateHistoryMalformedJSON(t *testing.T) {
	fake := &recordingBridge{out: []byte("not json")}
	code, _, stderr := runWithOptions([]string{"state", "history", "--sensor-id", "pir_01"}, Options{Bridge: fake})
	if code == 0 {
		t.Fatalf("expected failure for malformed JSON")
	}
	if !strings.Contains(stderr, "invalid JSON") {
		t.Fatalf("expected invalid JSON message, got stderr=%q", stderr)
	}
}
