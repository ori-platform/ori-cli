// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

// Package doctor computes operator-facing diagnostic summaries from a parsed
// runtime health snapshot. The summaries mirror the ori-sdk-python extended
// health helper contracts: they describe readiness signals without granting
// or denying action-tier authority, never infer deployment type, and never
// expose remote-command sender identities.
package doctor

import (
	"github.com/ori-platform/ori-cli/internal/rpc"
)

// Invariant authority models by action tier. Availability of gateways, alert
// channels, evidence, or Local SLM never changes these.
const (
	AuthorityAdvisory            = "advisory"
	AuthorityRuntimePolicy       = "runtime_policy"
	AuthorityOperatorApproval    = "operator_approval"
	AuthorityDeterministicSafety = "deterministic_safety"
)

// SensorFreshness carries freshness diagnostics for one runtime-reported
// sensor.
type SensorFreshness struct {
	SensorID        string   `json:"sensor_id"`
	DeltaMs         *int64   `json:"delta_ms"`
	TimestampStatus string   `json:"timestamp_status"`
	RuntimeStale    bool     `json:"runtime_stale"`
	DegradedReasons []string `json:"degraded_reasons"`
}

// SensorFreshnessSummary carries freshness diagnostics for all sensors.
type SensorFreshnessSummary struct {
	Sensors     []SensorFreshness `json:"sensors"`
	AnyDegraded bool              `json:"any_degraded"`
}

// AlertChannelSummary reports runtime alert-channel availability and the
// global outbox posture. Runtime availability never claims provider
// delivery, and the outbox is global rather than per-channel.
type AlertChannelSummary struct {
	SMSRuntimeAvailable      bool     `json:"sms_runtime_available"`
	WhatsAppRuntimeAvailable bool     `json:"whatsapp_runtime_available"`
	InternetAvailable        bool     `json:"internet_available"`
	OutboxBacklogCount       int64    `json:"outbox_backlog_count"`
	OutboxOldestAgeMs        *int64   `json:"outbox_oldest_age_ms"`
	Degraded                 bool     `json:"degraded"`
	DegradedReasons          []string `json:"degraded_reasons"`
}

// TierExecutionState separates the invariant authority model of one action
// tier from its observed execution readiness. ExecutionReady is nil when
// readiness depends on deployment context the health snapshot cannot prove.
type TierExecutionState struct {
	AuthorityModel  string   `json:"authority_model"`
	ExecutionReady  *bool    `json:"execution_ready"`
	DegradedReasons []string `json:"degraded_reasons"`
}

// TierCapabilitySummary carries execution diagnostics for all four tiers.
type TierCapabilitySummary struct {
	TierA TierExecutionState `json:"tier_a"`
	TierB TierExecutionState `json:"tier_b"`
	TierC TierExecutionState `json:"tier_c"`
	TierD TierExecutionState `json:"tier_d"`
}

// EvidenceSummary reports public evidence posture without validating or
// naming the private evidence-store implementation.
type EvidenceSummary struct {
	Enabled              bool     `json:"enabled"`
	Available            bool     `json:"available"`
	PublicKeyHex         string   `json:"public_key_hex"`
	ProtocolVersion      string   `json:"protocol_version"`
	ActionEventType      string   `json:"action_event_type"`
	ChainHeadHash        *string  `json:"chain_head_hash"`
	PendingExportCount   *int64   `json:"pending_export_count"`
	LastAttestedActionID *int64   `json:"last_attested_action_id"`
	AttestationGapCount  int64    `json:"attestation_gap_count"`
	Degraded             bool     `json:"degraded"`
	DegradedReasons      []string `json:"degraded_reasons"`
}

// RemoteCommandLockoutAggregate is an identity-free aggregate of
// remote-command sender risk. No sender identity, channel key, or reason
// text appears here.
type RemoteCommandLockoutAggregate struct {
	EnforcementEnabled bool `json:"enforcement_enabled"`
	TotalSenderCount   int  `json:"total_sender_count"`
	ElevatedCount      int  `json:"elevated_count"`
	CriticalCount      int  `json:"critical_count"`
	LockedOutCount     int  `json:"locked_out_count"`
	StaleCount         int  `json:"stale_count"`
	Degraded           bool `json:"degraded"`
}

// RuntimePostureSummary is the broad runtime posture with sender identities
// removed.
type RuntimePostureSummary struct {
	GatewayBrokerDegraded        bool                          `json:"gateway_broker_degraded"`
	StateStoreEncryptionDegraded bool                          `json:"state_store_encryption_degraded"`
	AlertOutboxDegraded          bool                          `json:"alert_outbox_degraded"`
	EvidenceDegraded             bool                          `json:"evidence_degraded"`
	RemoteCommandLockout         RemoteCommandLockoutAggregate `json:"remote_command_lockout"`
	Degraded                     bool                          `json:"degraded"`
	DegradedReasons              []string                      `json:"degraded_reasons"`
}

// Summary is the full ori doctor diagnostic report.
type Summary struct {
	OK              bool                   `json:"ok"`
	Command         string                 `json:"command"`
	DeviceID        string                 `json:"device_id,omitempty"`
	SensorFreshness SensorFreshnessSummary `json:"sensor_freshness"`
	AlertChannels   AlertChannelSummary    `json:"alert_channels"`
	Tiers           TierCapabilitySummary  `json:"tiers"`
	Evidence        EvidenceSummary        `json:"evidence"`
	Posture         RuntimePostureSummary  `json:"posture"`
	Degraded        bool                   `json:"degraded"`
}

// BuildSummary computes the full doctor report for one health snapshot.
// nowMs is the wall-clock time in milliseconds used for sensor deltas.
func BuildSummary(status rpc.RuntimeHealthStatus, nowMs int64) Summary {
	sensors := SensorFreshnessDelta(status, nowMs)
	alerts := AlertChannel(status)
	tiers := TierCapability(status)
	evidence := Evidence(status)
	posture := RuntimePosture(status)

	degraded := sensors.AnyDegraded || alerts.Degraded || evidence.Degraded || posture.Degraded ||
		tierNotReady(tiers.TierA) || tierNotReady(tiers.TierB) ||
		tierNotReady(tiers.TierC) || tierNotReady(tiers.TierD)

	return Summary{
		OK:              true,
		Command:         "doctor",
		DeviceID:        status.DeviceID,
		SensorFreshness: sensors,
		AlertChannels:   alerts,
		Tiers:           tiers,
		Evidence:        evidence,
		Posture:         posture,
		Degraded:        degraded,
	}
}

func tierNotReady(tier TierExecutionState) bool {
	return tier.ExecutionReady != nil && !*tier.ExecutionReady
}

// SensorFreshnessDelta returns signed timestamp deltas while preserving the
// runtime stale verdicts. A missing last_seen_ms yields a nil DeltaMs (never
// -1); future timestamps keep their negative delta unclamped. No second
// staleness threshold is invented from poll_interval_ms.
func SensorFreshnessDelta(status rpc.RuntimeHealthStatus, nowMs int64) SensorFreshnessSummary {
	sensors := []SensorFreshness{}
	anyDegraded := false

	for _, sensor := range status.Sensors {
		reasons := []string{}
		if !sensor.Connected {
			reasons = append(reasons, "sensor_disconnected")
		}

		var deltaMs *int64
		timestampStatus := "missing"
		if sensor.LastSeenMs == nil {
			reasons = append(reasons, "timestamp_missing")
		} else {
			delta := nowMs - *sensor.LastSeenMs
			deltaMs = &delta
			if delta < 0 {
				timestampStatus = "future"
				reasons = append(reasons, "timestamp_in_future")
			} else {
				timestampStatus = "observed"
			}
		}

		if sensor.Stale {
			reasons = append(reasons, "runtime_stale")
		}

		anyDegraded = anyDegraded || len(reasons) > 0
		sensors = append(sensors, SensorFreshness{
			SensorID:        sensor.ID,
			DeltaMs:         deltaMs,
			TimestampStatus: timestampStatus,
			RuntimeStale:    sensor.Stale,
			DegradedReasons: reasons,
		})
	}

	return SensorFreshnessSummary{Sensors: sensors, AnyDegraded: anyDegraded}
}

// AlertChannel summarizes runtime availability without claiming provider
// delivery.
func AlertChannel(status rpc.RuntimeHealthStatus) AlertChannelSummary {
	posture := status.CapabilityPosture
	reasons := []string{}

	smsAvailable, whatsappAvailable, internetAvailable := false, false, false
	if posture == nil || !posture.Available {
		reasons = append(reasons, "capability_posture_unavailable")
	} else {
		smsAvailable = posture.SMSAvailable
		whatsappAvailable = posture.WhatsAppAvailable
		internetAvailable = posture.InternetAvailable
		if !smsAvailable {
			reasons = append(reasons, "sms_runtime_unavailable")
		}
		if !whatsappAvailable {
			reasons = append(reasons, "whatsapp_runtime_unavailable")
		}
		if !internetAvailable {
			reasons = append(reasons, "internet_unavailable")
		}
	}

	var backlogCount int64
	var oldestAgeMs *int64
	if outbox := status.AlertOutbox; outbox != nil {
		backlogCount = outbox.BacklogCount
		oldestAgeMs = outbox.OldestQueuedAgeMs
	}
	if backlogCount > 0 {
		reasons = append(reasons, "alert_outbox_backlog")
	}

	return AlertChannelSummary{
		SMSRuntimeAvailable:      smsAvailable,
		WhatsAppRuntimeAvailable: whatsappAvailable,
		InternetAvailable:        internetAvailable,
		OutboxBacklogCount:       backlogCount,
		OutboxOldestAgeMs:        oldestAgeMs,
		Degraded:                 len(reasons) > 0,
		DegradedReasons:          reasons,
	}
}

// TierCapability separates invariant tier authority from observed execution
// readiness. Tier D authority is never reported as disabled by device
// policy, alert caps, evidence availability, gateway availability, or Local
// SLM availability. Deployment type is never inferred: physical readiness
// that depends on deployment context is reported as unknown.
func TierCapability(status rpc.RuntimeHealthStatus) TierCapabilitySummary {
	alerts := AlertChannel(status)
	posture := status.CapabilityPosture

	var tierAReady *bool
	if posture != nil && posture.Available {
		ready := posture.SMSAvailable || (posture.WhatsAppAvailable && posture.InternetAvailable)
		tierAReady = &ready
	}

	tierAReasons := make([]string, len(alerts.DegradedReasons))
	copy(tierAReasons, alerts.DegradedReasons)

	return TierCapabilitySummary{
		TierA: TierExecutionState{
			AuthorityModel:  AuthorityAdvisory,
			ExecutionReady:  tierAReady,
			DegradedReasons: tierAReasons,
		},
		TierB: physicalTierState(status, AuthorityRuntimePolicy, "relay_b_enabled"),
		TierC: physicalTierState(status, AuthorityOperatorApproval, "relay_c_enabled"),
		TierD: physicalTierState(status, AuthorityDeterministicSafety, ""),
	}
}

// Evidence summarizes public evidence metadata without validating artifact
// identity.
func Evidence(status rpc.RuntimeHealthStatus) EvidenceSummary {
	evidence := status.Evidence
	reasons := []string{}
	if evidence.Enabled && !evidence.Available {
		reasons = append(reasons, "evidence_unavailable")
	}
	if evidence.AttestationGapCount > 0 {
		reasons = append(reasons, "attestation_gaps_present")
	}

	return EvidenceSummary{
		Enabled:              evidence.Enabled,
		Available:            evidence.Available,
		PublicKeyHex:         evidence.PublicKeyHex,
		ProtocolVersion:      evidence.ProtocolVersion,
		ActionEventType:      evidence.ActionEventType,
		ChainHeadHash:        evidence.ChainHeadHash,
		PendingExportCount:   evidence.PendingExportCount,
		LastAttestedActionID: evidence.LastAttestedActionID,
		AttestationGapCount:  evidence.AttestationGapCount,
		Degraded:             len(reasons) > 0,
		DegradedReasons:      reasons,
	}
}

// RuntimePosture returns broad posture diagnostics with no sender-level
// information.
func RuntimePosture(status rpc.RuntimeHealthStatus) RuntimePostureSummary {
	gatewayDegraded := status.GatewayBrokerPosture == nil ||
		!status.GatewayBrokerPosture.Available ||
		(status.GatewayBrokerPosture.GatewayEnabled && status.GatewayBrokerPosture.RequiresACLHardening)
	encryptionDegraded := status.StateStoreEncryption == nil ||
		!status.StateStoreEncryption.Available ||
		(status.StateStoreEncryption.Mode == "filesystem_required" && !status.StateStoreEncryption.Satisfied)
	outboxDegraded := status.AlertOutbox != nil && status.AlertOutbox.BacklogCount > 0
	evidence := Evidence(status)
	lockout := remoteCommandLockoutAggregate(status)

	reasons := []string{}
	if gatewayDegraded {
		reasons = append(reasons, "gateway_broker_posture_degraded")
	}
	if encryptionDegraded {
		reasons = append(reasons, "state_store_encryption_degraded")
	}
	if outboxDegraded {
		reasons = append(reasons, "alert_outbox_degraded")
	}
	if evidence.Degraded {
		reasons = append(reasons, "evidence_degraded")
	}
	if lockout.Degraded {
		reasons = append(reasons, "remote_command_lockout_degraded")
	}

	return RuntimePostureSummary{
		GatewayBrokerDegraded:        gatewayDegraded,
		StateStoreEncryptionDegraded: encryptionDegraded,
		AlertOutboxDegraded:          outboxDegraded,
		EvidenceDegraded:             evidence.Degraded,
		RemoteCommandLockout:         lockout,
		Degraded:                     len(reasons) > 0,
		DegradedReasons:              reasons,
	}
}

func physicalTierState(status rpc.RuntimeHealthStatus, authorityModel, policyField string) TierExecutionState {
	reasons := []string{}
	executionBlocked := false

	if posture := status.CapabilityPosture; posture == nil || !posture.Available {
		reasons = append(reasons, "capability_posture_unavailable")
	} else if !posture.RelayConnected {
		reasons = append(reasons, "relay_disconnected")
		executionBlocked = true
	}

	if policyField != "" {
		if policy := status.DevicePolicy; policy != nil && policy.Enabled {
			if !policy.Available {
				reasons = append(reasons, "device_policy_unavailable")
			} else {
				if policy.IsExpired != nil && *policy.IsExpired {
					reasons = append(reasons, "device_policy_expired")
					executionBlocked = true
				} else if policy.IsExpired == nil {
					reasons = append(reasons, "device_policy_state_incomplete")
				}

				var policyValue *bool
				var disabledReason string
				if policyField == "relay_b_enabled" {
					policyValue = policy.RelayBEnabled
					disabledReason = "device_policy_relay_b_disabled"
				} else {
					policyValue = policy.RelayCEnabled
					disabledReason = "device_policy_relay_c_disabled"
				}
				switch {
				case policyValue != nil && !*policyValue:
					reasons = append(reasons, disabledReason)
					executionBlocked = true
				case policyValue == nil && !hasReason(reasons, "device_policy_state_incomplete"):
					reasons = append(reasons, "device_policy_state_incomplete")
				}
			}
		}
	}

	if executionBlocked {
		ready := false
		return TierExecutionState{
			AuthorityModel:  authorityModel,
			ExecutionReady:  &ready,
			DegradedReasons: reasons,
		}
	}

	reasons = append(reasons, "deployment_context_unavailable")
	return TierExecutionState{
		AuthorityModel:  authorityModel,
		ExecutionReady:  nil,
		DegradedReasons: reasons,
	}
}

func remoteCommandLockoutAggregate(status rpc.RuntimeHealthStatus) RemoteCommandLockoutAggregate {
	lockout := status.RemoteCommandLockout
	if lockout == nil {
		return RemoteCommandLockoutAggregate{}
	}

	aggregate := RemoteCommandLockoutAggregate{
		EnforcementEnabled: lockout.EnforcementEnabled,
		TotalSenderCount:   len(lockout.Senders),
	}
	for _, sender := range lockout.Senders {
		switch sender.RiskLevel {
		case "elevated":
			aggregate.ElevatedCount++
		case "critical":
			aggregate.CriticalCount++
		}
		if sender.LockedOut {
			aggregate.LockedOutCount++
		}
		if sender.Stale {
			aggregate.StaleCount++
		}
	}
	aggregate.Degraded = aggregate.ElevatedCount > 0 || aggregate.CriticalCount > 0 ||
		aggregate.LockedOutCount > 0 || aggregate.StaleCount > 0
	return aggregate
}

func hasReason(reasons []string, want string) bool {
	for _, reason := range reasons {
		if reason == want {
			return true
		}
	}
	return false
}
