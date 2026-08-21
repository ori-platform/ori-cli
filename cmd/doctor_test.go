// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ori-platform/ori-cli/internal/bridge"
	"github.com/ori-platform/ori-cli/internal/rpc"
)

const doctorHealthPayload = `{"schema_version":1,"ok":true,"health":{` +
	`"device_id":"edge-doc","uptime_s":12.5,"health_socket_path":"/tmp/ori-health.sock",` +
	`"capability_posture":{"available":true,"sms_available":true,"whatsapp_available":false,` +
	`"gateway_reachable":false,"local_slm_loaded":false,"relay_connected":true,"internet_available":true,` +
	`"checked_at_ms":100,"expires_at_ms":200,"gateway_last_heartbeat_ms":null},` +
	`"sensors":[{"id":"meter-1","type":"power","protocol":"modbus","poll_interval_ms":1000,` +
	`"connected":true,"last_seen_ms":5000,"stale":false}],` +
	`"alert_outbox":{"backlog_count":0,"oldest_queued_original_ts":null,"oldest_queued_age_ms":null,` +
	`"retry_interval_minutes":0.5,"max_non_tier_d_attempts":10,"tier_d_critical_warning_threshold":3,"batch_size":50},` +
	`"device_policy":{"available":false,"enabled":false},` +
	`"remote_command_lockout":{"enforcement_enabled":false,"risk_window_ms":3600000,"stale_after_ms":3600000,` +
	`"incident_sender_limit":50,"senders":[{"channel":"sms","from_number":"+27000SECRET","risk_level":"normal",` +
	`"reason":"below_threshold","locked_out":false,"enforcement_enabled":false,"stale":false,` +
	`"incident_count":0,"rejection_count":0,"window_ms":3600000,"checked_at_ms":700}]},` +
	`"gateway_broker_posture":{"available":true,"gateway_enabled":false,"require_credentials":false,` +
	`"credentials_configured":false,"requires_acl_hardening":false,"deployment_check":"warning",` +
	`"anonymous_access":"unknown","acl_policy":"unknown"},` +
	`"state_store_encryption":{"available":true,"satisfied":false,"marker_configured":false,` +
	`"path_prefix_configured":false,"mode":"disabled"},` +
	`"evidence":{"enabled":true,"available":true,"public_key_hex":"aabb","artifact_version":"0.2.0",` +
	`"protocol_version":"evidence.v1","action_event_type":"SAFETY_ACTION_EXECUTED","chain_head_hash":"ccdd",` +
	`"pending_export_count":0,"last_attested_action_id":7,"attestation_gap_count":0,"status_counts":{"signed":7}}}}`

func doctorBridgeEnvelope(inner string) []byte {
	return []byte(`{"schema_version":1,"ok":true,"command":"health snapshot","result":` + inner + `}` + "\n")
}

type doctorFakeBridge struct {
	stdout []byte
	err    error
	calls  [][]string
}

func (f *doctorFakeBridge) Run(_ context.Context, args ...string) (bridge.Result, error) {
	f.calls = append(f.calls, args)
	return bridge.Result{Stdout: f.stdout}, f.err
}

func doctorHealthyStatus(t *testing.T) rpc.RuntimeHealthStatus {
	t.Helper()
	status, err := rpc.ParseHealth([]byte(doctorHealthPayload + "\n"))
	if err != nil {
		t.Fatalf("ParseHealth fixture: %v", err)
	}
	return status
}

func TestDoctorTextViaBridge(t *testing.T) {
	fakeBridge := &doctorFakeBridge{stdout: doctorBridgeEnvelope(doctorHealthPayload)}
	getHealthCalled := false
	getHealth := func(context.Context, string) (rpc.RuntimeHealthStatus, error) {
		getHealthCalled = true
		return rpc.RuntimeHealthStatus{}, errors.New("socket should not be needed")
	}

	var stdout, stderr bytes.Buffer
	code := ExecuteWithOptions([]string{"doctor"}, &stdout, &stderr, Options{
		Bridge: fakeBridge, GetHealth: getHealth,
	})
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr.String())
	}
	if getHealthCalled {
		t.Fatal("direct socket must not be used when the bridge succeeds")
	}
	out := stdout.String()
	for _, want := range []string{
		"ori doctor:", "Device: edge-doc", "meter-1",
		"Tier D deterministic_safety", "evidence.v1", "SAFETY_ACTION_EXECUTED",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("doctor output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Fatalf("doctor text output must not contain ANSI:\n%s", out)
	}
	if strings.Contains(out, "+27000SECRET") || strings.Contains(out, "below_threshold") {
		t.Fatalf("doctor output leaks sender identity:\n%s", out)
	}
}

func TestDoctorJSONDeterministicAndRedacted(t *testing.T) {
	run := func() string {
		fakeBridge := &doctorFakeBridge{stdout: doctorBridgeEnvelope(doctorHealthPayload)}
		var stdout, stderr bytes.Buffer
		code := ExecuteWithOptions([]string{"doctor", "--json"}, &stdout, &stderr, Options{
			Bridge: fakeBridge,
			GetHealth: func(context.Context, string) (rpc.RuntimeHealthStatus, error) {
				return rpc.RuntimeHealthStatus{}, errors.New("unused")
			},
			// Freeze the clock: delta_ms derives from now, so a live clock
			// makes byte-identical output a race.
			NowMs: func() int64 { return 1753000006000 },
		})
		if code != 0 {
			t.Fatalf("exit = %d, stderr = %s", code, stderr.String())
		}
		return stdout.String()
	}

	first := run()
	second := run()
	if first != second {
		t.Fatalf("doctor --json must be deterministic:\n%s\n---\n%s", first, second)
	}

	var decoded map[string]any
	if err := json.Unmarshal([]byte(first), &decoded); err != nil {
		t.Fatalf("doctor --json must emit valid JSON: %v", err)
	}
	for _, want := range []string{`"sensor_freshness"`, `"alert_channels"`, `"tiers"`, `"posture"`} {
		if !strings.Contains(first, want) {
			t.Fatalf("doctor --json missing %s:\n%s", want, first)
		}
	}
	if strings.Contains(first, "\x1b[") {
		t.Fatal("doctor --json must not contain ANSI")
	}
	for _, leaked := range []string{"+27000SECRET", "from_number", "below_threshold"} {
		if strings.Contains(first, leaked) {
			t.Fatalf("doctor --json leaks sender identity %q:\n%s", leaked, first)
		}
	}
}

// The health payload these tests drive still carries artifact_version, as a
// v1 runtime sends it. Both operator surfaces must drop it on the floor.
//
// The render was already guarded on a non-empty value, so adopting
// runtime-health/v2 in the runtime would have made the line disappear on its
// own. That is exactly why the field is deleted rather than left to lapse: a
// disclosure that stops by accident can restart the same way, and a future
// runtime reporting the field again would silently restore the render. With
// no field to render, the property holds whatever the runtime sends.
func TestDoctorOmitsArtifactIdentityFromALegacyRuntime(t *testing.T) {
	if !strings.Contains(doctorHealthPayload, `"artifact_version":"0.2.0"`) {
		t.Fatal("fixture must carry artifact_version, or this test proves nothing")
	}

	run := func(args ...string) string {
		fakeBridge := &doctorFakeBridge{stdout: doctorBridgeEnvelope(doctorHealthPayload)}
		var stdout, stderr bytes.Buffer
		code := ExecuteWithOptions(append([]string{"doctor"}, args...), &stdout, &stderr, Options{
			Bridge: fakeBridge,
			GetHealth: func(context.Context, string) (rpc.RuntimeHealthStatus, error) {
				return rpc.RuntimeHealthStatus{}, errors.New("unused")
			},
			NowMs: func() int64 { return 1753000006000 },
		})
		if code != 0 {
			t.Fatalf("exit = %d, stderr = %s", code, stderr.String())
		}
		return stdout.String()
	}

	for _, surface := range []struct {
		name string
		out  string
	}{
		{"text", run()},
		{"json", run("--json")},
	} {
		for _, leaked := range []string{"artifact:", "artifact_version", "0.2.0"} {
			if strings.Contains(surface.out, leaked) {
				t.Fatalf("doctor %s renders artifact identity %q:\n%s", surface.name, leaked, surface.out)
			}
		}
		// Removal must not have taken the public posture with it: an operator
		// still has to be able to see that this device can sign, and against
		// which contract, or degradation stops being noticeable.
		for _, want := range []string{"evidence.v1", "SAFETY_ACTION_EXECUTED"} {
			if !strings.Contains(surface.out, want) {
				t.Fatalf("doctor %s lost evidence posture %q:\n%s", surface.name, want, surface.out)
			}
		}
	}
}

func TestDoctorFallsBackToSocket(t *testing.T) {
	fakeBridge := &doctorFakeBridge{err: errors.New("python3 not found")}
	status := doctorHealthyStatus(t)
	var stdout, stderr bytes.Buffer
	code := ExecuteWithOptions([]string{"doctor"}, &stdout, &stderr, Options{
		Bridge: fakeBridge,
		GetHealth: func(context.Context, string) (rpc.RuntimeHealthStatus, error) {
			return status, nil
		},
	})
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr.String())
	}
	if len(fakeBridge.calls) == 0 || strings.Join(fakeBridge.calls[0], " ") != "health snapshot --socket "+rpc.DefaultHealthSocket {
		t.Fatalf("bridge must be attempted first, calls = %v", fakeBridge.calls)
	}
	if !strings.Contains(stdout.String(), "Device: edge-doc") {
		t.Fatalf("fallback output:\n%s", stdout.String())
	}
}

func TestDoctorFallsBackWhenBridgePayloadFailsContract(t *testing.T) {
	broken := `{"schema_version":1,"ok":true,"health":{"device_id":"edge-doc"}}`
	fakeBridge := &doctorFakeBridge{stdout: doctorBridgeEnvelope(broken)}
	status := doctorHealthyStatus(t)
	var stdout, stderr bytes.Buffer
	code := ExecuteWithOptions([]string{"doctor"}, &stdout, &stderr, Options{
		Bridge: fakeBridge,
		GetHealth: func(context.Context, string) (rpc.RuntimeHealthStatus, error) {
			return status, nil
		},
	})
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Device: edge-doc") {
		t.Fatalf("fallback output:\n%s", stdout.String())
	}
}

func TestDoctorUnavailableExitsNonZero(t *testing.T) {
	fakeBridge := &doctorFakeBridge{err: errors.New("python3 not found")}
	var stdout, stderr bytes.Buffer
	code := ExecuteWithOptions([]string{"doctor"}, &stdout, &stderr, Options{
		Bridge: fakeBridge,
		GetHealth: func(context.Context, string) (rpc.RuntimeHealthStatus, error) {
			return rpc.RuntimeHealthStatus{}, errors.New("dial unix /run/ori/health.sock: connect: no such file or directory")
		},
	})
	if code == 0 {
		t.Fatal("unreachable runtime must exit non-zero")
	}
	if !strings.Contains(stderr.String(), "runtime health unavailable") {
		t.Fatalf("stderr = %s", stderr.String())
	}
}

func TestDoctorDegradedStillExitsZero(t *testing.T) {
	degraded := strings.Replace(doctorHealthPayload, `"backlog_count":0`, `"backlog_count":4`, 1)
	fakeBridge := &doctorFakeBridge{stdout: doctorBridgeEnvelope(degraded)}
	var stdout, stderr bytes.Buffer
	code := ExecuteWithOptions([]string{"doctor"}, &stdout, &stderr, Options{
		Bridge: fakeBridge,
		GetHealth: func(context.Context, string) (rpc.RuntimeHealthStatus, error) {
			return rpc.RuntimeHealthStatus{}, errors.New("unused")
		},
	})
	if code != 0 {
		t.Fatalf("degraded report must exit zero, exit = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "ori doctor: DEGRADED") {
		t.Fatalf("expected degraded overall:\n%s", stdout.String())
	}
}

// hangingBridge blocks until its context deadline, simulating a bridge
// process that never answers.
type hangingBridge struct{}

func (h *hangingBridge) Run(ctx context.Context, _ ...string) (bridge.Result, error) {
	<-ctx.Done()
	return bridge.Result{}, ctx.Err()
}

func TestDoctorSocketFallbackSurvivesBridgeTimeout(t *testing.T) {
	origOverall, origBridgeTimeout := doctorOverallTimeout, doctorBridgeTimeout
	doctorOverallTimeout = 2 * time.Second
	doctorBridgeTimeout = 100 * time.Millisecond
	defer func() {
		doctorOverallTimeout = origOverall
		doctorBridgeTimeout = origBridgeTimeout
	}()

	status := doctorHealthyStatus(t)
	socketSawLiveContext := false
	var stdout, stderr bytes.Buffer
	code := ExecuteWithOptions([]string{"doctor"}, &stdout, &stderr, Options{
		Bridge: &hangingBridge{},
		GetHealth: func(ctx context.Context, _ string) (rpc.RuntimeHealthStatus, error) {
			socketSawLiveContext = ctx.Err() == nil
			return status, nil
		},
	})
	if code != 0 {
		t.Fatalf("socket fallback must serve after bridge timeout, exit = %d, stderr = %s", code, stderr.String())
	}
	if !socketSawLiveContext {
		t.Fatal("socket fallback received an already-cancelled context")
	}
	if !strings.Contains(stdout.String(), "Device: edge-doc") {
		t.Fatalf("fallback output:\n%s", stdout.String())
	}
}

func TestDoctorSocketFlagReachesBridge(t *testing.T) {
	fakeBridge := &doctorFakeBridge{stdout: doctorBridgeEnvelope(doctorHealthPayload)}
	var stdout, stderr bytes.Buffer
	code := ExecuteWithOptions(
		[]string{"doctor", "--socket", "/data/data/com.termux/files/home/.ori/health.sock"},
		&stdout, &stderr,
		Options{
			Bridge: fakeBridge,
			GetHealth: func(context.Context, string) (rpc.RuntimeHealthStatus, error) {
				return rpc.RuntimeHealthStatus{}, errors.New("unused")
			},
		},
	)
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr.String())
	}
	joined := strings.Join(fakeBridge.calls[0], " ")
	if !strings.Contains(joined, "--socket /data/data/com.termux/files/home/.ori/health.sock") {
		t.Fatalf("socket flag not forwarded, calls = %v", fakeBridge.calls)
	}
}
