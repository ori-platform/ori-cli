// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ori-platform/ori-cli/internal/rpc"
)

func int64Ptr(v int64) *int64    { return &v }
func boolPtr(v bool) *bool       { return &v }
func stringPtr(v string) *string { return &v }

func availablePosture() *rpc.CapabilityPosture {
	return &rpc.CapabilityPosture{
		Available:         true,
		SMSAvailable:      true,
		WhatsAppAvailable: true,
		RelayConnected:    true,
		InternetAvailable: true,
	}
}

func assertReasons(t *testing.T, got []string, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("reasons = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("reasons = %v, want %v", got, want)
		}
	}
}

func TestSensorFreshnessDelta(t *testing.T) {
	now := int64(10_000)
	status := rpc.RuntimeHealthStatus{
		Sensors: []rpc.SensorStatus{
			{ID: "healthy", Connected: true, LastSeenMs: int64Ptr(9_000), Stale: false},
			{ID: "missing", Connected: true, LastSeenMs: nil, Stale: false},
			{ID: "future", Connected: true, LastSeenMs: int64Ptr(12_000), Stale: false},
			{ID: "stale", Connected: true, LastSeenMs: int64Ptr(9_500), Stale: true},
			{ID: "disconnected", Connected: false, LastSeenMs: int64Ptr(9_500), Stale: false},
		},
	}

	summary := SensorFreshnessDelta(status, now)
	if len(summary.Sensors) != 5 {
		t.Fatalf("sensors = %d, want 5", len(summary.Sensors))
	}
	if !summary.AnyDegraded {
		t.Fatal("expected any_degraded with degraded sensors present")
	}

	healthy := summary.Sensors[0]
	if healthy.DeltaMs == nil || *healthy.DeltaMs != 1_000 {
		t.Fatalf("healthy delta = %v, want 1000", healthy.DeltaMs)
	}
	if healthy.TimestampStatus != "observed" || healthy.RuntimeStale {
		t.Fatalf("healthy = %+v", healthy)
	}
	assertReasons(t, healthy.DegradedReasons)

	missing := summary.Sensors[1]
	if missing.DeltaMs != nil {
		t.Fatalf("missing delta = %v, want nil (never -1)", *missing.DeltaMs)
	}
	if missing.TimestampStatus != "missing" {
		t.Fatalf("missing timestamp_status = %q", missing.TimestampStatus)
	}
	assertReasons(t, missing.DegradedReasons, "timestamp_missing")

	future := summary.Sensors[2]
	if future.DeltaMs == nil || *future.DeltaMs != -2_000 {
		t.Fatalf("future delta = %v, want -2000 unclamped", future.DeltaMs)
	}
	if future.TimestampStatus != "future" {
		t.Fatalf("future timestamp_status = %q", future.TimestampStatus)
	}
	assertReasons(t, future.DegradedReasons, "timestamp_in_future")

	stale := summary.Sensors[3]
	if !stale.RuntimeStale {
		t.Fatal("runtime stale verdict must be preserved independently")
	}
	assertReasons(t, stale.DegradedReasons, "runtime_stale")

	disconnected := summary.Sensors[4]
	assertReasons(t, disconnected.DegradedReasons, "sensor_disconnected")
}

func TestSensorFreshnessDeltaHealthySet(t *testing.T) {
	status := rpc.RuntimeHealthStatus{
		Sensors: []rpc.SensorStatus{
			{ID: "meter-1", Connected: true, LastSeenMs: int64Ptr(900), Stale: false},
		},
	}
	summary := SensorFreshnessDelta(status, 1_000)
	if summary.AnyDegraded {
		t.Fatalf("healthy sensor set must not degrade: %+v", summary)
	}
}

func TestAlertChannelSummary(t *testing.T) {
	t.Run("posture unavailable", func(t *testing.T) {
		summary := AlertChannel(rpc.RuntimeHealthStatus{})
		if !summary.Degraded {
			t.Fatal("expected degraded when capability posture is unavailable")
		}
		assertReasons(t, summary.DegradedReasons, "capability_posture_unavailable")
	})

	t.Run("channels and backlog", func(t *testing.T) {
		posture := availablePosture()
		posture.SMSAvailable = false
		posture.InternetAvailable = false
		status := rpc.RuntimeHealthStatus{
			CapabilityPosture: posture,
			AlertOutbox:       &rpc.AlertOutboxState{BacklogCount: 3, OldestQueuedAgeMs: int64Ptr(60_000)},
		}
		summary := AlertChannel(status)
		assertReasons(t, summary.DegradedReasons,
			"sms_runtime_unavailable", "internet_unavailable", "alert_outbox_backlog")
		if summary.OutboxBacklogCount != 3 {
			t.Fatalf("backlog = %d, want 3", summary.OutboxBacklogCount)
		}
		if summary.OutboxOldestAgeMs == nil || *summary.OutboxOldestAgeMs != 60_000 {
			t.Fatalf("oldest age = %v, want 60000", summary.OutboxOldestAgeMs)
		}
		if summary.SMSRuntimeAvailable {
			t.Fatal("sms must report runtime unavailable")
		}
		if !summary.WhatsAppRuntimeAvailable {
			t.Fatal("whatsapp must report runtime available")
		}
	})

	t.Run("healthy", func(t *testing.T) {
		status := rpc.RuntimeHealthStatus{
			CapabilityPosture: availablePosture(),
			AlertOutbox:       &rpc.AlertOutboxState{},
		}
		summary := AlertChannel(status)
		if summary.Degraded {
			t.Fatalf("healthy channels must not degrade: %v", summary.DegradedReasons)
		}
	})
}

func TestTierCapabilitySummary(t *testing.T) {
	status := rpc.RuntimeHealthStatus{
		CapabilityPosture: availablePosture(),
		AlertOutbox:       &rpc.AlertOutboxState{},
	}
	summary := TierCapability(status)

	if summary.TierA.AuthorityModel != AuthorityAdvisory ||
		summary.TierB.AuthorityModel != AuthorityRuntimePolicy ||
		summary.TierC.AuthorityModel != AuthorityOperatorApproval ||
		summary.TierD.AuthorityModel != AuthorityDeterministicSafety {
		t.Fatalf("authority models are invariant: %+v", summary)
	}

	if summary.TierA.ExecutionReady == nil || !*summary.TierA.ExecutionReady {
		t.Fatalf("tier A must be ready with sms available: %+v", summary.TierA)
	}
	for name, tier := range map[string]TierExecutionState{
		"B": summary.TierB, "C": summary.TierC, "D": summary.TierD,
	} {
		if tier.ExecutionReady != nil {
			t.Fatalf("tier %s readiness must be unknown without deployment context: %+v", name, tier)
		}
		assertReasons(t, tier.DegradedReasons, "deployment_context_unavailable")
	}
}

func TestTierCapabilityPostureUnavailable(t *testing.T) {
	summary := TierCapability(rpc.RuntimeHealthStatus{})
	if summary.TierA.ExecutionReady != nil {
		t.Fatalf("tier A readiness must be unknown when posture unavailable: %+v", summary.TierA)
	}
	assertReasons(t, summary.TierA.DegradedReasons, "capability_posture_unavailable")
	assertReasons(t, summary.TierB.DegradedReasons,
		"capability_posture_unavailable", "deployment_context_unavailable")
}

func TestTierCapabilityRelayDisconnected(t *testing.T) {
	posture := availablePosture()
	posture.RelayConnected = false
	status := rpc.RuntimeHealthStatus{CapabilityPosture: posture}
	summary := TierCapability(status)

	for name, tier := range map[string]TierExecutionState{
		"B": summary.TierB, "C": summary.TierC, "D": summary.TierD,
	} {
		if tier.ExecutionReady == nil || *tier.ExecutionReady {
			t.Fatalf("tier %s must be not ready with relay disconnected: %+v", name, tier)
		}
		if tier.DegradedReasons[0] != "relay_disconnected" {
			t.Fatalf("tier %s reasons = %v, want relay_disconnected first", name, tier.DegradedReasons)
		}
	}
}

func TestTierCapabilityDevicePolicy(t *testing.T) {
	posture := availablePosture()

	t.Run("relay disabled by policy", func(t *testing.T) {
		status := rpc.RuntimeHealthStatus{
			CapabilityPosture: posture,
			DevicePolicy: &rpc.DevicePolicyState{
				Available: true, Enabled: true,
				IsExpired: boolPtr(false), RelayBEnabled: boolPtr(false), RelayCEnabled: boolPtr(true),
			},
		}
		summary := TierCapability(status)
		if summary.TierB.ExecutionReady == nil || *summary.TierB.ExecutionReady {
			t.Fatalf("tier B must be not ready: %+v", summary.TierB)
		}
		assertReasons(t, summary.TierB.DegradedReasons, "device_policy_relay_b_disabled")
		if summary.TierC.ExecutionReady != nil {
			t.Fatalf("tier C must stay unknown: %+v", summary.TierC)
		}
	})

	t.Run("policy expired", func(t *testing.T) {
		status := rpc.RuntimeHealthStatus{
			CapabilityPosture: posture,
			DevicePolicy: &rpc.DevicePolicyState{
				Available: true, Enabled: true,
				IsExpired: boolPtr(true), RelayBEnabled: boolPtr(true),
			},
		}
		summary := TierCapability(status)
		if summary.TierB.ExecutionReady == nil || *summary.TierB.ExecutionReady {
			t.Fatalf("tier B must be not ready with expired policy: %+v", summary.TierB)
		}
		assertReasons(t, summary.TierB.DegradedReasons, "device_policy_expired")
	})

	t.Run("policy state incomplete", func(t *testing.T) {
		status := rpc.RuntimeHealthStatus{
			CapabilityPosture: posture,
			DevicePolicy: &rpc.DevicePolicyState{
				Available: true, Enabled: true,
				IsExpired: nil, RelayBEnabled: nil,
			},
		}
		summary := TierCapability(status)
		assertReasons(t, summary.TierB.DegradedReasons,
			"device_policy_state_incomplete", "deployment_context_unavailable")
		if summary.TierB.ExecutionReady != nil {
			t.Fatalf("incomplete policy must not block readiness: %+v", summary.TierB)
		}
	})

	t.Run("policy enabled but unavailable", func(t *testing.T) {
		status := rpc.RuntimeHealthStatus{
			CapabilityPosture: posture,
			DevicePolicy:      &rpc.DevicePolicyState{Available: false, Enabled: true},
		}
		summary := TierCapability(status)
		assertReasons(t, summary.TierB.DegradedReasons,
			"device_policy_unavailable", "deployment_context_unavailable")
	})
}

func TestTierDIgnoresNonAuthoritativeSignals(t *testing.T) {
	// Device policy disabled relays, expired policy, evidence unavailable,
	// gateway down: none of these may redefine Tier D authority or block it.
	status := rpc.RuntimeHealthStatus{
		CapabilityPosture: availablePosture(),
		DevicePolicy: &rpc.DevicePolicyState{
			Available: true, Enabled: true,
			IsExpired: boolPtr(true), RelayBEnabled: boolPtr(false), RelayCEnabled: boolPtr(false),
		},
		Evidence: rpc.EvidenceStatus{Enabled: true, Available: false},
	}
	summary := TierCapability(status)
	if summary.TierD.AuthorityModel != AuthorityDeterministicSafety {
		t.Fatalf("tier D authority = %q", summary.TierD.AuthorityModel)
	}
	if summary.TierD.ExecutionReady != nil {
		t.Fatalf("tier D readiness must stay unknown, never policy-blocked: %+v", summary.TierD)
	}
	assertReasons(t, summary.TierD.DegradedReasons, "deployment_context_unavailable")
}

func TestEvidenceSummary(t *testing.T) {
	t.Run("healthy", func(t *testing.T) {
		summary := Evidence(rpc.RuntimeHealthStatus{
			Evidence: rpc.EvidenceStatus{
				Enabled: true, Available: true, PublicKeyHex: "ab12",
				ProtocolVersion: "evidence.v1",
				ActionEventType: "SAFETY_ACTION_EXECUTED",
				ChainHeadHash:   stringPtr("9f"), PendingExportCount: int64Ptr(3),
				LastAttestedActionID: int64Ptr(42),
			},
		})
		if summary.Degraded {
			t.Fatalf("healthy evidence must not degrade: %v", summary.DegradedReasons)
		}
		if summary.ProtocolVersion != "evidence.v1" || summary.ActionEventType != "SAFETY_ACTION_EXECUTED" {
			t.Fatalf("evidence summary = %+v", summary)
		}
	})

	t.Run("unavailable with gaps", func(t *testing.T) {
		summary := Evidence(rpc.RuntimeHealthStatus{
			Evidence: rpc.EvidenceStatus{Enabled: true, Available: false, AttestationGapCount: 2},
		})
		assertReasons(t, summary.DegradedReasons, "evidence_unavailable", "attestation_gaps_present")
	})

	t.Run("disabled is not degraded", func(t *testing.T) {
		summary := Evidence(rpc.RuntimeHealthStatus{
			Evidence: rpc.EvidenceStatus{Enabled: false, Available: false},
		})
		if summary.Degraded {
			t.Fatalf("disabled evidence must not degrade: %v", summary.DegradedReasons)
		}
	})
}

func TestRuntimePostureSummary(t *testing.T) {
	t.Run("healthy", func(t *testing.T) {
		summary := RuntimePosture(rpc.RuntimeHealthStatus{
			GatewayBrokerPosture: &rpc.GatewayBrokerPosture{Available: true, GatewayEnabled: true},
			StateStoreEncryption: &rpc.StateStoreEncryptionPosture{Available: true, Mode: "disabled"},
			AlertOutbox:          &rpc.AlertOutboxState{},
			RemoteCommandLockout: &rpc.RemoteCommandLockoutState{},
		})
		if summary.Degraded {
			t.Fatalf("healthy posture must not degrade: %v", summary.DegradedReasons)
		}
	})

	t.Run("nil blocks degrade gateway and encryption only", func(t *testing.T) {
		summary := RuntimePosture(rpc.RuntimeHealthStatus{})
		if !summary.GatewayBrokerDegraded || !summary.StateStoreEncryptionDegraded {
			t.Fatalf("nil blocks must degrade: %+v", summary)
		}
		if summary.AlertOutboxDegraded || summary.EvidenceDegraded {
			t.Fatalf("absent outbox/evidence must not degrade: %+v", summary)
		}
	})

	t.Run("acl hardening and unsatisfied encryption", func(t *testing.T) {
		summary := RuntimePosture(rpc.RuntimeHealthStatus{
			GatewayBrokerPosture: &rpc.GatewayBrokerPosture{
				Available: true, GatewayEnabled: true, RequiresACLHardening: true,
			},
			StateStoreEncryption: &rpc.StateStoreEncryptionPosture{
				Available: true, Mode: "filesystem_required", Satisfied: false,
			},
			AlertOutbox: &rpc.AlertOutboxState{BacklogCount: 1},
		})
		assertReasons(t, summary.DegradedReasons,
			"gateway_broker_posture_degraded", "state_store_encryption_degraded", "alert_outbox_degraded")
	})

	t.Run("lockout aggregate counts without identities", func(t *testing.T) {
		summary := RuntimePosture(rpc.RuntimeHealthStatus{
			GatewayBrokerPosture: &rpc.GatewayBrokerPosture{Available: true},
			StateStoreEncryption: &rpc.StateStoreEncryptionPosture{Available: true, Mode: "disabled"},
			RemoteCommandLockout: &rpc.RemoteCommandLockoutState{
				EnforcementEnabled: true,
				Senders: []rpc.RemoteCommandLockoutSender{
					{Channel: "sms", FromNumber: "+270001", Reason: "below_threshold", RiskLevel: "normal"},
					{Channel: "sms", FromNumber: "+270002", Reason: "elevated_incidents", RiskLevel: "elevated", Stale: true},
					{Channel: "whatsapp", FromNumber: "+270003", Reason: "critical_incidents", RiskLevel: "critical", LockedOut: true},
				},
			},
		})
		lockout := summary.RemoteCommandLockout
		if lockout.TotalSenderCount != 3 || lockout.ElevatedCount != 1 ||
			lockout.CriticalCount != 1 || lockout.LockedOutCount != 1 || lockout.StaleCount != 1 {
			t.Fatalf("lockout aggregate = %+v", lockout)
		}
		if !lockout.Degraded || !summary.Degraded {
			t.Fatal("elevated/critical/locked/stale senders must degrade the aggregate")
		}
		assertReasons(t, summary.DegradedReasons, "remote_command_lockout_degraded")
	})

	t.Run("enforcement disabled alone is not degraded", func(t *testing.T) {
		summary := RuntimePosture(rpc.RuntimeHealthStatus{
			GatewayBrokerPosture: &rpc.GatewayBrokerPosture{Available: true},
			StateStoreEncryption: &rpc.StateStoreEncryptionPosture{Available: true, Mode: "disabled"},
			RemoteCommandLockout: &rpc.RemoteCommandLockoutState{EnforcementEnabled: false},
		})
		if summary.RemoteCommandLockout.Degraded || summary.Degraded {
			t.Fatalf("disabled enforcement alone must not degrade: %+v", summary)
		}
		if summary.RemoteCommandLockout.EnforcementEnabled {
			t.Fatal("enforcement flag must stay visible")
		}
	})
}

func TestSummaryJSONContract(t *testing.T) {
	status := rpc.RuntimeHealthStatus{
		DeviceID:          "edge-1",
		CapabilityPosture: availablePosture(),
		AlertOutbox:       &rpc.AlertOutboxState{},
		Sensors: []rpc.SensorStatus{
			{ID: "meter-1", Connected: true, LastSeenMs: int64Ptr(9_000)},
		},
		Evidence: rpc.EvidenceStatus{Enabled: true, Available: true, PublicKeyHex: "ab12"},
		RemoteCommandLockout: &rpc.RemoteCommandLockoutState{
			Senders: []rpc.RemoteCommandLockoutSender{
				{Channel: "sms", FromNumber: "+27000SECRET", Reason: "critical_incidents", RiskLevel: "critical", LockedOut: true},
			},
		},
	}

	raw, err := json.Marshal(BuildSummary(status, 10_000))
	if err != nil {
		t.Fatalf("marshal summary: %v", err)
	}
	js := string(raw)

	for _, key := range []string{
		`"sensor_freshness"`, `"alert_channels"`, `"tiers"`, `"evidence"`, `"posture"`,
		`"tier_a"`, `"tier_b"`, `"tier_c"`, `"tier_d"`,
		`"authority_model"`, `"execution_ready"`, `"degraded_reasons"`,
		`"remote_command_lockout"`, `"total_sender_count"`, `"attestation_gap_count"`,
		`"delta_ms"`, `"timestamp_status"`, `"runtime_stale"`,
	} {
		if !strings.Contains(js, key) {
			t.Fatalf("summary JSON missing %s: %s", key, js)
		}
	}

	// Sender identities must never appear in any summary output.
	for _, leaked := range []string{"+27000SECRET", "from_number", "critical_incidents", `"channel"`} {
		if strings.Contains(js, leaked) {
			t.Fatalf("summary JSON leaks sender identity %q: %s", leaked, js)
		}
	}

	// Tri-state readiness: unknown serializes as null, never omitted.
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal summary: %v", err)
	}
	tiers := decoded["tiers"].(map[string]any)
	tierB := tiers["tier_b"].(map[string]any)
	if ready, present := tierB["execution_ready"]; !present || ready != nil {
		t.Fatalf("tier_b execution_ready = %v (present=%t), want explicit null", ready, present)
	}
	// Missing sensor timestamps serialize as null too.
	freshness := decoded["sensor_freshness"].(map[string]any)
	sensors := freshness["sensors"].([]any)
	first := sensors[0].(map[string]any)
	if first["delta_ms"].(float64) != 1_000 {
		t.Fatalf("delta_ms = %v, want 1000", first["delta_ms"])
	}
}

func TestBuildSummaryOverallDegraded(t *testing.T) {
	healthy := BuildSummary(rpc.RuntimeHealthStatus{
		CapabilityPosture:    availablePosture(),
		AlertOutbox:          &rpc.AlertOutboxState{},
		GatewayBrokerPosture: &rpc.GatewayBrokerPosture{Available: true},
		StateStoreEncryption: &rpc.StateStoreEncryptionPosture{Available: true, Mode: "disabled"},
	}, 1_000)
	if healthy.Degraded {
		t.Fatal("healthy snapshot must not be degraded overall")
	}
	if !healthy.OK || healthy.Command != "doctor" {
		t.Fatalf("summary envelope = %+v", healthy)
	}

	blocked := BuildSummary(rpc.RuntimeHealthStatus{
		CapabilityPosture:    availablePosture(),
		AlertOutbox:          &rpc.AlertOutboxState{},
		GatewayBrokerPosture: &rpc.GatewayBrokerPosture{Available: true},
		StateStoreEncryption: &rpc.StateStoreEncryptionPosture{Available: true, Mode: "disabled"},
		DevicePolicy: &rpc.DevicePolicyState{
			Available: true, Enabled: true, IsExpired: boolPtr(false), RelayBEnabled: boolPtr(false),
		},
	}, 1_000)
	if !blocked.Degraded {
		t.Fatal("policy-blocked tier must degrade the overall summary")
	}
}
