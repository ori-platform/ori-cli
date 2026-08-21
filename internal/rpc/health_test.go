// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package rpc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGetHealthUsesRuntimeSocketProtocol(t *testing.T) {
	socketPath := filepath.Join(os.TempDir(), fmt.Sprintf("ori-cli-health-%d.sock", time.Now().UnixNano()))
	_ = os.Remove(socketPath)
	t.Cleanup(func() { _ = os.Remove(socketPath) })
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}
	defer listener.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		defer conn.Close()

		buf := make([]byte, len("GET_HEALTH\n"))
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Errorf("read request: %v", err)
			return
		}
		if string(buf) != "GET_HEALTH\n" {
			t.Errorf("request = %q, want GET_HEALTH newline", string(buf))
			return
		}
		_, _ = conn.Write([]byte("{\"status\":\"ok\",\"device_id\":\"edge-1\"}\n"))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := GetHealth(ctx, socketPath)
	if err != nil {
		t.Fatalf("GetHealth: %v", err)
	}
	if got.Status != "ok" || got.DeviceID != "edge-1" {
		t.Fatalf("health = %#v", got)
	}
	<-done
}

func TestParseHealthRejectsInvalidJSON(t *testing.T) {
	_, err := ParseHealth([]byte("not-json\n"))
	if err == nil || !strings.Contains(err.Error(), "decode runtime health JSON") {
		t.Fatalf("expected decode error, got %v", err)
	}
}

func TestParseHealthReadsWrappedEnvelope(t *testing.T) {
	payload := []byte(`{"schema_version":1,"ok":true,"health":{"device_id":"edge-2","evidence":{"enabled":true,"available":true,"public_key_hex":"aabbccdd"}}}` + "\n")
	got, err := ParseHealth(payload)
	if err != nil {
		t.Fatalf("ParseHealth: %v", err)
	}
	if got.DeviceID != "edge-2" {
		t.Fatalf("DeviceID = %q, want edge-2", got.DeviceID)
	}
	if !got.Evidence.Enabled {
		t.Fatal("expected Evidence.Enabled = true")
	}
	if !got.Evidence.Available {
		t.Fatal("expected Evidence.Available = true")
	}
	if got.Evidence.PublicKeyHex != "aabbccdd" {
		t.Fatalf("Evidence.PublicKeyHex = %q, want aabbccdd", got.Evidence.PublicKeyHex)
	}
	if !got.Canonical {
		t.Fatal("expected wrapped v1 response to be marked canonical")
	}
}

func TestParseHealthReadsFlatLegacyResponse(t *testing.T) {
	payload := []byte(`{"status":"ok","device_id":"edge-3"}` + "\n")
	got, err := ParseHealth(payload)
	if err != nil {
		t.Fatalf("ParseHealth: %v", err)
	}
	if got.Status != "ok" {
		t.Fatalf("Status = %q, want ok", got.Status)
	}
	if got.DeviceID != "edge-3" {
		t.Fatalf("DeviceID = %q, want edge-3", got.DeviceID)
	}
	if got.Canonical {
		t.Fatal("legacy flat response must not be marked canonical")
	}
}

func TestParseHealthRejectsMissingEvidence(t *testing.T) {
	payload := []byte(`{"schema_version":1,"ok":true,"health":{"device_id":"edge-4"}}` + "\n")
	_, err := ParseHealth(payload)
	if err == nil {
		t.Fatal("expected missing canonical evidence object to fail closed")
	}
	if !strings.Contains(err.Error(), "missing required evidence object") {
		t.Fatalf("expected missing evidence error, got %v", err)
	}
}

func TestParseHealthRejectsOkFalse(t *testing.T) {
	payload := []byte(`{"schema_version":1,"ok":false,"error":{"code":"internal_error","detail":"snapshot failed"}}` + "\n")
	_, err := ParseHealth(payload)
	if err == nil {
		t.Fatal("expected error for ok=false envelope")
	}
	if !strings.Contains(err.Error(), "internal_error") || !strings.Contains(err.Error(), "snapshot failed") {
		t.Fatalf("expected structured error, got %v", err)
	}
}

func TestParseHealthRejectsOkFalseWithoutErrorDetails(t *testing.T) {
	payload := []byte(`{"schema_version":1,"ok":false}` + "\n")
	_, err := ParseHealth(payload)
	if err == nil {
		t.Fatal("expected error for ok=false envelope")
	}
	if !strings.Contains(err.Error(), "health_request_failed") {
		t.Fatalf("expected default error code, got %v", err)
	}
}

func TestParseHealthRejectsNonBooleanOk(t *testing.T) {
	payload := []byte(`{"schema_version":1,"ok":"true","health":{"device_id":"edge-5"}}` + "\n")
	_, err := ParseHealth(payload)
	if err == nil {
		t.Fatal("expected error for non-boolean ok")
	}
	if !strings.Contains(err.Error(), "non-boolean ok") {
		t.Fatalf("expected non-boolean ok error, got %v", err)
	}
}

func TestParseHealthRejectsUnsupportedSchemaVersion(t *testing.T) {
	payload := []byte(`{"schema_version":2,"ok":true,"health":{"device_id":"edge-5"}}` + "\n")
	_, err := ParseHealth(payload)
	if err == nil {
		t.Fatal("expected error for unsupported schema_version")
	}
	if !strings.Contains(err.Error(), "unsupported schema_version") {
		t.Fatalf("expected schema version error, got %v", err)
	}
}

func TestParseHealthRejectsMissingHealth(t *testing.T) {
	payload := []byte(`{"schema_version":1,"ok":true,"device_id":"edge-6"}` + "\n")
	_, err := ParseHealth(payload)
	if err == nil {
		t.Fatal("expected error when health is missing from canonical envelope")
	}
	if !strings.Contains(err.Error(), "health is missing or not an object") {
		t.Fatalf("expected missing health error, got %v", err)
	}
}

func TestParseHealthRejectsMalformedEvidenceFields(t *testing.T) {
	tests := []struct {
		name     string
		evidence string
		want     string
	}{
		{
			name:     "evidence is not object",
			evidence: `"enabled"`,
			want:     "evidence field is not an object",
		},
		{
			name:     "enabled is not boolean",
			evidence: `{"enabled":"true","available":false,"public_key_hex":""}`,
			want:     "enabled field is not boolean",
		},
		{
			name:     "available is not boolean",
			evidence: `{"enabled":true,"available":1,"public_key_hex":""}`,
			want:     "available field is not boolean",
		},
		{
			name:     "public key is not string",
			evidence: `{"enabled":true,"available":true,"public_key_hex":false}`,
			want:     "public_key_hex field is not a string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := []byte(`{"schema_version":1,"ok":true,"health":{"device_id":"edge-7","evidence":` + tt.evidence + `}}`)
			_, err := ParseHealth(payload)
			if err == nil {
				t.Fatal("expected malformed evidence field to fail closed")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected %q error, got %v", tt.want, err)
			}
		})
	}
}

func TestParseHealthRejectsMissingRequiredEvidenceFields(t *testing.T) {
	tests := []struct {
		name     string
		evidence string
		want     string
	}{
		{
			name:     "enabled",
			evidence: `{"available":false,"public_key_hex":""}`,
			want:     "missing required enabled field",
		},
		{
			name:     "available",
			evidence: `{"enabled":false,"public_key_hex":""}`,
			want:     "missing required available field",
		},
		{
			name:     "public key",
			evidence: `{"enabled":false,"available":false}`,
			want:     "missing required public_key_hex field",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := []byte(`{"schema_version":1,"ok":true,"health":{"device_id":"edge-8","evidence":` + tt.evidence + `}}`)
			_, err := ParseHealth(payload)
			if err == nil {
				t.Fatal("expected missing evidence field to fail closed")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected %q error, got %v", tt.want, err)
			}
		})
	}
}

func TestParseHealthRejectsNonObjectHealth(t *testing.T) {
	payload := []byte(`{"schema_version":1,"ok":true,"health":"not-an-object"}` + "\n")
	_, err := ParseHealth(payload)
	if err == nil {
		t.Fatal("expected error when health is not an object")
	}
	if !strings.Contains(err.Error(), "health is missing or not an object") {
		t.Fatalf("expected non-object health error, got %v", err)
	}
}

const v2HealthPayload = `{"schema_version":1,"ok":true,"health":{` +
	`"device_id":"edge-9","uptime_s":12.5,"health_socket_path":"/tmp/ori-health.sock",` +
	`"capability_posture":{"available":true,"sms_available":false,"whatsapp_available":true,` +
	`"gateway_reachable":false,"local_slm_loaded":false,"relay_connected":true,"internet_available":true,` +
	`"checked_at_ms":100,"expires_at_ms":200,"gateway_last_heartbeat_ms":null},` +
	`"sensors":[` +
	`{"id":"meter-1","type":"power","protocol":"modbus","poll_interval_ms":1000,"connected":true,"last_seen_ms":5000,"stale":false},` +
	`{"id":"temp-1","type":"temperature","protocol":"gpio","poll_interval_ms":2000,"connected":false,"last_seen_ms":null,"stale":true}],` +
	`"last_alert_timestamps":{"by_channel":{"sms":100},"by_trigger":{"x":200}},` +
	`"alert_outbox":{"backlog_count":2,"oldest_queued_original_ts":400,"oldest_queued_age_ms":600,` +
	`"retry_interval_minutes":0.5,"max_non_tier_d_attempts":10,"tier_d_critical_warning_threshold":3,"batch_size":50},` +
	`"device_policy":{"available":true,"enabled":true,"policy_version":3,"tier":"standard",` +
	`"relay_b_enabled":true,"relay_c_enabled":false,"cloud_llm_enabled":null,` +
	`"alert_sms_monthly_cap":100,"alert_whatsapp_monthly_cap":50,"valid_until":999,"issued_at":111,"is_expired":false},` +
	`"remote_command_lockout":{"enforcement_enabled":true,"risk_window_ms":3600000,"stale_after_ms":3600000,` +
	`"incident_sender_limit":50,"senders":[{"channel":"sms","from_number":"+27000SECRET","risk_level":"critical",` +
	`"reason":"critical_incidents","locked_out":true,"enforcement_enabled":true,"stale":false,` +
	`"incident_count":4,"rejection_count":1,"window_ms":3600000,"checked_at_ms":700}]},` +
	`"gateway_broker_posture":{"available":true,"gateway_enabled":true,"require_credentials":true,` +
	`"credentials_configured":true,"requires_acl_hardening":false,"deployment_check":"warning",` +
	`"anonymous_access":"disabled","acl_policy":"per_device_required"},` +
	`"state_store_encryption":{"available":true,"satisfied":true,"marker_configured":true,` +
	`"path_prefix_configured":true,"mode":"filesystem_required"},` +
	`"evidence":{"enabled":true,"available":true,"public_key_hex":"aabb","artifact_version":"0.2.0",` +
	`"protocol_version":"evidence.v1","action_event_type":"SAFETY_ACTION_EXECUTED","chain_head_hash":"ccdd",` +
	`"pending_export_count":2,"last_attested_action_id":42,"attestation_gap_count":1,"status_counts":{"signed":40}}}}`

func TestParseHealthReadsV2Payload(t *testing.T) {
	got, err := ParseHealth([]byte(v2HealthPayload + "\n"))
	if err != nil {
		t.Fatalf("ParseHealth: %v", err)
	}
	if got.DeviceID != "edge-9" || got.UptimeS != 12.5 || got.HealthSocketPath != "/tmp/ori-health.sock" {
		t.Fatalf("top-level fields = %+v", got)
	}

	posture := got.CapabilityPosture
	if posture == nil || !posture.Available || posture.SMSAvailable || !posture.WhatsAppAvailable ||
		!posture.RelayConnected || !posture.InternetAvailable {
		t.Fatalf("capability posture = %+v", posture)
	}
	if posture.GatewayLastHeartbeatMs != nil {
		t.Fatalf("gateway heartbeat = %v, want nil", *posture.GatewayLastHeartbeatMs)
	}

	if len(got.Sensors) != 2 {
		t.Fatalf("sensors = %d, want 2", len(got.Sensors))
	}
	if got.Sensors[0].LastSeenMs == nil || *got.Sensors[0].LastSeenMs != 5000 {
		t.Fatalf("meter-1 last_seen = %v", got.Sensors[0].LastSeenMs)
	}
	if got.Sensors[1].LastSeenMs != nil || !got.Sensors[1].Stale || got.Sensors[1].Connected {
		t.Fatalf("temp-1 = %+v", got.Sensors[1])
	}

	outbox := got.AlertOutbox
	if outbox == nil || outbox.BacklogCount != 2 || outbox.OldestQueuedAgeMs == nil ||
		*outbox.OldestQueuedAgeMs != 600 || outbox.RetryIntervalMinutes != 0.5 {
		t.Fatalf("alert outbox = %+v", outbox)
	}

	policy := got.DevicePolicy
	if policy == nil || !policy.Available || !policy.Enabled {
		t.Fatalf("device policy = %+v", policy)
	}
	if policy.RelayCEnabled == nil || *policy.RelayCEnabled {
		t.Fatalf("relay_c_enabled = %v, want false", policy.RelayCEnabled)
	}
	if policy.IsExpired == nil || *policy.IsExpired {
		t.Fatalf("is_expired = %v, want false", policy.IsExpired)
	}
	if policy.AlertSMSMonthlyCap == nil || *policy.AlertSMSMonthlyCap != 100 {
		t.Fatalf("sms cap = %v", policy.AlertSMSMonthlyCap)
	}

	lockout := got.RemoteCommandLockout
	if lockout == nil || !lockout.EnforcementEnabled || len(lockout.Senders) != 1 {
		t.Fatalf("lockout = %+v", lockout)
	}
	sender := lockout.Senders[0]
	if sender.RiskLevel != "critical" || !sender.LockedOut || sender.IncidentCount != 4 {
		t.Fatalf("sender = %+v", sender)
	}

	broker := got.GatewayBrokerPosture
	if broker == nil || !broker.Available || broker.DeploymentCheck != "warning" ||
		broker.ACLPolicy != "per_device_required" {
		t.Fatalf("gateway broker = %+v", broker)
	}

	encryption := got.StateStoreEncryption
	if encryption == nil || encryption.Mode != "filesystem_required" || !encryption.Satisfied {
		t.Fatalf("encryption = %+v", encryption)
	}

	// The payload above still carries artifact_version, as a v1 runtime sends
	// it. Parsing must accept it and ignore it, so the assertion is on the
	// fields that survive rather than on the one that was dropped.
	evidence := got.Evidence
	if evidence.ProtocolVersion != "evidence.v1" ||
		evidence.ActionEventType != "SAFETY_ACTION_EXECUTED" {
		t.Fatalf("evidence = %+v", evidence)
	}
	if evidence.ChainHeadHash == nil || *evidence.ChainHeadHash != "ccdd" {
		t.Fatalf("chain head = %v", evidence.ChainHeadHash)
	}
	if evidence.PendingExportCount == nil || *evidence.PendingExportCount != 2 {
		t.Fatalf("pending exports = %v", evidence.PendingExportCount)
	}
	if evidence.LastAttestedActionID == nil || *evidence.LastAttestedActionID != 42 {
		t.Fatalf("last attested = %v", evidence.LastAttestedActionID)
	}
	if evidence.AttestationGapCount != 1 || evidence.StatusCounts["signed"] != 40 {
		t.Fatalf("evidence counts = %+v", evidence)
	}
}

func TestParseHealthRedactsSenderIdentities(t *testing.T) {
	t.Run("canonical", func(t *testing.T) {
		got, err := ParseHealth([]byte(v2HealthPayload + "\n"))
		if err != nil {
			t.Fatalf("ParseHealth: %v", err)
		}
		raw, err := json.Marshal(got)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		for _, leaked := range []string{"+27000SECRET", "critical_incidents", "from_number"} {
			if strings.Contains(string(raw), leaked) {
				t.Fatalf("raw passthrough leaks %q: %s", leaked, raw)
			}
		}
		// Aggregate-safe fields survive in the typed model.
		if got.RemoteCommandLockout.Senders[0].RiskLevel != "critical" {
			t.Fatal("typed sender aggregate fields must survive redaction")
		}
	})

	t.Run("legacy", func(t *testing.T) {
		payload := []byte(`{"status":"ok","remote_command_lockout":{"enforcement_enabled":false,` +
			`"senders":[{"channel":"sms","from_number":"+27000SECRET","reason":"critical_incidents"}]}}` + "\n")
		got, err := ParseHealth(payload)
		if err != nil {
			t.Fatalf("ParseHealth: %v", err)
		}
		raw, err := json.Marshal(got)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		for _, leaked := range []string{"+27000SECRET", "critical_incidents"} {
			if strings.Contains(string(raw), leaked) {
				t.Fatalf("legacy raw passthrough leaks %q: %s", leaked, raw)
			}
		}
	})
}

func TestParseHealthRedactsEvidenceArtifactIdentity(t *testing.T) {
	// Removing the typed field does not remove the key from Raw, and
	// MarshalJSON returns Raw untouched whenever it is present. Every surface
	// that prints the runtime payload directly goes through this path.
	assertRedacted := func(t *testing.T, got RuntimeHealthStatus) {
		t.Helper()
		raw, err := json.Marshal(got)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		for _, leaked := range []string{"artifact_version", "0.2.0"} {
			if strings.Contains(string(raw), leaked) {
				t.Fatalf("raw passthrough leaks %q: %s", leaked, raw)
			}
		}
		// Redaction must be surgical: the public posture an operator needs in
		// order to notice degradation stays in the same object.
		for _, want := range []string{"evidence.v1", "public_key_hex"} {
			if !strings.Contains(string(raw), want) {
				t.Fatalf("raw passthrough lost evidence posture %q: %s", want, raw)
			}
		}
	}

	t.Run("canonical", func(t *testing.T) {
		if !strings.Contains(v2HealthPayload, `"artifact_version":"0.2.0"`) {
			t.Fatal("fixture must carry artifact_version, or this test proves nothing")
		}
		got, err := ParseHealth([]byte(v2HealthPayload + "\n"))
		if err != nil {
			t.Fatalf("ParseHealth: %v", err)
		}
		assertRedacted(t, got)
		if got.Evidence.ProtocolVersion != "evidence.v1" {
			t.Fatal("typed evidence posture must survive redaction")
		}
	})

	t.Run("legacy", func(t *testing.T) {
		payload := []byte(`{"status":"ok","evidence":{"enabled":true,"available":true,` +
			`"public_key_hex":"aabb","artifact_version":"0.2.0","protocol_version":"evidence.v1",` +
			`"action_event_type":"SAFETY_ACTION_EXECUTED"}}` + "\n")
		got, err := ParseHealth(payload)
		if err != nil {
			t.Fatalf("ParseHealth: %v", err)
		}
		assertRedacted(t, got)
	})

	t.Run("evidence absent is not a panic", func(t *testing.T) {
		if _, err := ParseHealth([]byte(`{"status":"ok"}` + "\n")); err != nil {
			t.Fatalf("ParseHealth: %v", err)
		}
	})

	// The typed parse for this key was removed with the field, so it is no
	// longer type-checked. A malformed value is dropped rather than refused,
	// which is correct for a legacy key nothing reads — a runtime sending it
	// must keep working — but it is a deliberate narrowing of what this
	// parser rejects, so it is pinned here rather than left implied.
	t.Run("malformed artifact_version is ignored, not rejected", func(t *testing.T) {
		for _, value := range []string{`123`, `{"nested":true}`, `null`, `["a"]`} {
			payload := []byte(`{"status":"ok","evidence":{"enabled":true,"available":true,` +
				`"public_key_hex":"aabb","artifact_version":` + value +
				`,"protocol_version":"evidence.v1"}}` + "\n")
			got, err := ParseHealth(payload)
			if err != nil {
				t.Fatalf("artifact_version %s must be ignored, not rejected: %v", value, err)
			}
			raw, err := json.Marshal(got)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if strings.Contains(string(raw), "artifact_version") {
				t.Fatalf("artifact_version %s survived redaction: %s", value, raw)
			}
			if got.Evidence.ProtocolVersion != "evidence.v1" {
				t.Fatalf("artifact_version %s disturbed the surviving posture", value)
			}
		}
	})
}

func TestParseHealthToleratesMissingV2Blocks(t *testing.T) {
	payload := []byte(`{"schema_version":1,"ok":true,"health":{"device_id":"edge-10",` +
		`"evidence":{"enabled":false,"available":false,"public_key_hex":""}}}` + "\n")
	got, err := ParseHealth(payload)
	if err != nil {
		t.Fatalf("ParseHealth: %v", err)
	}
	if got.CapabilityPosture != nil || got.AlertOutbox != nil || got.DevicePolicy != nil ||
		got.RemoteCommandLockout != nil || got.GatewayBrokerPosture != nil ||
		got.StateStoreEncryption != nil || len(got.Sensors) != 0 {
		t.Fatalf("absent v2 blocks must parse as absent: %+v", got)
	}
}

func TestParseHealthRejectsMalformedV2Blocks(t *testing.T) {
	tests := []struct {
		name  string
		block string
		want  string
	}{
		{
			name:  "sensors not array",
			block: `"sensors":"nope",`,
			want:  "sensors field is not an array",
		},
		{
			name:  "capability posture wrong type",
			block: `"capability_posture":{"available":"yes"},`,
			want:  "available field is not boolean",
		},
		{
			name: "sender missing identity field",
			block: `"remote_command_lockout":{"enforcement_enabled":true,"risk_window_ms":1,` +
				`"stale_after_ms":1,"incident_sender_limit":1,"senders":[{"channel":"sms"}]},`,
			want: "missing required from_number field",
		},
		{
			name:  "outbox wrong type",
			block: `"alert_outbox":{"backlog_count":"2"},`,
			want:  "backlog_count field is not an integer",
		},
		{
			name:  "block not object",
			block: `"device_policy":"nope",`,
			want:  "device_policy field is not an object",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := []byte(`{"schema_version":1,"ok":true,"health":{` + tt.block +
				`"evidence":{"enabled":false,"available":false,"public_key_hex":""}}}` + "\n")
			_, err := ParseHealth(payload)
			if err == nil {
				t.Fatal("expected malformed v2 block to fail closed")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected %q error, got %v", tt.want, err)
			}
		})
	}
}
