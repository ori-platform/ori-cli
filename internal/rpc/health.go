// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package rpc

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
)

const DefaultHealthSocket = "/run/ori/health.sock"

// EvidenceStatus is the runtime health evidence block that describes the
// evidence layer signing state on the device. Enabled, Available and
// PublicKeyHex are required in the canonical v1 envelope; the remaining
// fields are optional evidence posture metadata reported by v2 runtimes.
// ProtocolVersion is the opaque public alias reported by the runtime; the
// CLI must never validate or name the private artifact implementation.
type EvidenceStatus struct {
	Enabled              bool             `json:"enabled"`
	Available            bool             `json:"available"`
	PublicKeyHex         string           `json:"public_key_hex"`
	ArtifactVersion      string           `json:"artifact_version,omitempty"`
	ProtocolVersion      string           `json:"protocol_version,omitempty"`
	ActionEventType      string           `json:"action_event_type,omitempty"`
	ChainHeadHash        *string          `json:"chain_head_hash,omitempty"`
	PendingExportCount   *int64           `json:"pending_export_count,omitempty"`
	LastAttestedActionID *int64           `json:"last_attested_action_id,omitempty"`
	AttestationGapCount  int64            `json:"attestation_gap_count,omitempty"`
	StatusCounts         map[string]int64 `json:"status_counts,omitempty"`
}

// CapabilityPosture mirrors the runtime v2 capability_posture block.
type CapabilityPosture struct {
	Available              bool   `json:"available"`
	SMSAvailable           bool   `json:"sms_available"`
	WhatsAppAvailable      bool   `json:"whatsapp_available"`
	GatewayReachable       bool   `json:"gateway_reachable"`
	LocalSLMLoaded         bool   `json:"local_slm_loaded"`
	RelayConnected         bool   `json:"relay_connected"`
	InternetAvailable      bool   `json:"internet_available"`
	CheckedAtMs            int64  `json:"checked_at_ms"`
	ExpiresAtMs            int64  `json:"expires_at_ms"`
	GatewayLastHeartbeatMs *int64 `json:"gateway_last_heartbeat_ms,omitempty"`
}

// SensorStatus mirrors one entry of the runtime v2 sensors array.
// LastSeenMs is nil when the runtime reports null.
type SensorStatus struct {
	ID             string `json:"id"`
	Type           string `json:"type"`
	Protocol       string `json:"protocol"`
	PollIntervalMs int64  `json:"poll_interval_ms"`
	Connected      bool   `json:"connected"`
	LastSeenMs     *int64 `json:"last_seen_ms"`
	Stale          bool   `json:"stale"`
}

// AlertTimestamps mirrors the runtime v2 last_alert_timestamps block.
type AlertTimestamps struct {
	ByChannel map[string]int64 `json:"by_channel"`
	ByTrigger map[string]int64 `json:"by_trigger"`
}

// AlertOutboxState mirrors the runtime v2 alert_outbox block.
type AlertOutboxState struct {
	BacklogCount                  int64   `json:"backlog_count"`
	OldestQueuedOriginalTs        *int64  `json:"oldest_queued_original_ts"`
	OldestQueuedAgeMs             *int64  `json:"oldest_queued_age_ms"`
	RetryIntervalMinutes          float64 `json:"retry_interval_minutes"`
	MaxNonTierDAttempts           int64   `json:"max_non_tier_d_attempts"`
	TierDCriticalWarningThreshold int64   `json:"tier_d_critical_warning_threshold"`
	BatchSize                     int64   `json:"batch_size"`
}

// DevicePolicyState mirrors the runtime v2 device_policy block. The whole
// block may be absent in the no-dispatcher fallback; all detail fields are
// nullable to preserve the runtime's null distinction.
type DevicePolicyState struct {
	Available               bool    `json:"available"`
	Enabled                 bool    `json:"enabled"`
	PolicyVersion           *int64  `json:"policy_version"`
	Tier                    *string `json:"tier"`
	RelayBEnabled           *bool   `json:"relay_b_enabled"`
	RelayCEnabled           *bool   `json:"relay_c_enabled"`
	CloudLLMEnabled         *bool   `json:"cloud_llm_enabled"`
	AlertSMSMonthlyCap      *int64  `json:"alert_sms_monthly_cap"`
	AlertWhatsAppMonthlyCap *int64  `json:"alert_whatsapp_monthly_cap"`
	ValidUntil              *int64  `json:"valid_until"`
	IssuedAt                *int64  `json:"issued_at"`
	IsExpired               *bool   `json:"is_expired"`
}

// RemoteCommandLockoutSender mirrors one entry of the runtime v2
// remote_command_lockout senders array. FromNumber and Channel are
// sender-identifying PII: they are parsed here only so aggregate counts can
// be derived, and must never appear in doctor output.
type RemoteCommandLockoutSender struct {
	Channel            string `json:"channel"`
	FromNumber         string `json:"from_number"`
	RiskLevel          string `json:"risk_level"`
	Reason             string `json:"reason"`
	LockedOut          bool   `json:"locked_out"`
	EnforcementEnabled bool   `json:"enforcement_enabled"`
	Stale              bool   `json:"stale"`
	IncidentCount      int64  `json:"incident_count"`
	RejectionCount     int64  `json:"rejection_count"`
	WindowMs           int64  `json:"window_ms"`
	CheckedAtMs        int64  `json:"checked_at_ms"`
}

// RemoteCommandLockoutState mirrors the runtime v2 remote_command_lockout
// block.
type RemoteCommandLockoutState struct {
	EnforcementEnabled  bool                         `json:"enforcement_enabled"`
	RiskWindowMs        int64                        `json:"risk_window_ms"`
	StaleAfterMs        int64                        `json:"stale_after_ms"`
	IncidentSenderLimit int64                        `json:"incident_sender_limit"`
	Senders             []RemoteCommandLockoutSender `json:"senders"`
}

// GatewayBrokerPosture mirrors the runtime v2 gateway_broker_posture block.
type GatewayBrokerPosture struct {
	Available             bool   `json:"available"`
	GatewayEnabled        bool   `json:"gateway_enabled"`
	RequireCredentials    bool   `json:"require_credentials"`
	CredentialsConfigured bool   `json:"credentials_configured"`
	RequiresACLHardening  bool   `json:"requires_acl_hardening"`
	DeploymentCheck       string `json:"deployment_check"`
	AnonymousAccess       string `json:"anonymous_access"`
	ACLPolicy             string `json:"acl_policy"`
}

// StateStoreEncryptionPosture mirrors the runtime v2 state_store_encryption
// block.
type StateStoreEncryptionPosture struct {
	Available            bool   `json:"available"`
	Satisfied            bool   `json:"satisfied"`
	MarkerConfigured     bool   `json:"marker_configured"`
	PathPrefixConfigured bool   `json:"path_prefix_configured"`
	Mode                 string `json:"mode"`
}

// RuntimeHealthStatus is the parsed runtime health snapshot. Nested v2
// blocks are pointers so an absent block is distinguishable from a present
// one; doctor summaries degrade gracefully when they are nil.
type RuntimeHealthStatus struct {
	Status               string                       `json:"status,omitempty"`
	DeviceID             string                       `json:"device_id,omitempty"`
	UptimeS              float64                      `json:"uptime_s,omitempty"`
	HealthSocketPath     string                       `json:"health_socket_path,omitempty"`
	Evidence             EvidenceStatus               `json:"evidence,omitempty"`
	CapabilityPosture    *CapabilityPosture           `json:"capability_posture,omitempty"`
	Sensors              []SensorStatus               `json:"sensors,omitempty"`
	LastAlertTimestamps  *AlertTimestamps             `json:"last_alert_timestamps,omitempty"`
	AlertOutbox          *AlertOutboxState            `json:"alert_outbox,omitempty"`
	DevicePolicy         *DevicePolicyState           `json:"device_policy,omitempty"`
	RemoteCommandLockout *RemoteCommandLockoutState   `json:"remote_command_lockout,omitempty"`
	GatewayBrokerPosture *GatewayBrokerPosture        `json:"gateway_broker_posture,omitempty"`
	StateStoreEncryption *StateStoreEncryptionPosture `json:"state_store_encryption,omitempty"`
	Canonical            bool                         `json:"-"`
	Raw                  map[string]any               `json:"-"`
}

func (s RuntimeHealthStatus) MarshalJSON() ([]byte, error) {
	if s.Raw != nil {
		return json.Marshal(s.Raw)
	}
	type alias RuntimeHealthStatus
	return json.Marshal(alias(s))
}

func (s RuntimeHealthStatus) StatusOrUnknown() string {
	if s.Status == "" {
		return "unknown"
	}
	return s.Status
}

func GetHealth(ctx context.Context, socketPath string) (RuntimeHealthStatus, error) {
	if socketPath == "" {
		socketPath = DefaultHealthSocket
	}
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return RuntimeHealthStatus{}, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if _, err := conn.Write([]byte("GET_HEALTH\n")); err != nil {
		return RuntimeHealthStatus{}, err
	}
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		return RuntimeHealthStatus{}, err
	}
	return ParseHealth(line)
}

// ParseHealth parses a runtime health JSON response. It accepts the canonical
// wrapped envelope {"ok":true,"health":{...}}. For backward compatibility it
// also accepts the legacy flat form {"status":"ok","device_id":"..."} only
// when the "ok" envelope field is entirely absent.
func ParseHealth(payload []byte) (RuntimeHealthStatus, error) {
	var envelope map[string]any
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return RuntimeHealthStatus{}, fmt.Errorf("decode runtime health JSON: %w", err)
	}

	// Canonical runtime response is wrapped in {"schema_version":1,"ok":true,"health":{...}}.
	if _, present := envelope["ok"]; present {
		schemaVersion, schemaVersionIsNumber := envelope["schema_version"].(float64)
		if !schemaVersionIsNumber || schemaVersion != 1 {
			return RuntimeHealthStatus{}, fmt.Errorf("runtime health envelope has unsupported schema_version")
		}
		ok, okIsBool := envelope["ok"].(bool)
		if !okIsBool {
			return RuntimeHealthStatus{}, fmt.Errorf("runtime health envelope has non-boolean ok field")
		}
		if !ok {
			code := "health_request_failed"
			detail := "runtime health snapshot returned ok=false"
			if errObj, ok := envelope["error"].(map[string]any); ok {
				if c, ok := errObj["code"].(string); ok && c != "" {
					code = c
				}
				if d, ok := errObj["detail"].(string); ok && d != "" {
					detail = d
				}
			}
			return RuntimeHealthStatus{}, fmt.Errorf("runtime health error %s: %s", code, detail)
		}

		health, healthIsObject := envelope["health"].(map[string]any)
		if !healthIsObject {
			return RuntimeHealthStatus{}, fmt.Errorf("runtime health envelope ok=true but health is missing or not an object")
		}

		status := RuntimeHealthStatus{Canonical: true, Raw: envelope}
		if value, ok := health["status"].(string); ok {
			status.Status = value
		}
		if value, ok := health["device_id"].(string); ok {
			status.DeviceID = value
		}
		evidenceValue, evidencePresent := health["evidence"]
		if !evidencePresent {
			return RuntimeHealthStatus{}, fmt.Errorf("runtime health canonical payload is missing required evidence object")
		}
		evidence, err := parseEvidence(evidenceValue, true)
		if err != nil {
			return RuntimeHealthStatus{}, err
		}
		status.Evidence = evidence
		if err := parseHealthV2Blocks(health, &status); err != nil {
			return RuntimeHealthStatus{}, err
		}
		// Redact only after the typed parse: sender identities stay
		// available to aggregate counts but never to Raw passthrough output.
		redactSenderIdentities(health)
		return status, nil
	}

	// Legacy flat response without an envelope wrapper.
	status := RuntimeHealthStatus{Raw: envelope}
	redactSenderIdentities(envelope)
	if value, ok := envelope["status"].(string); ok {
		status.Status = value
	}
	if value, ok := envelope["device_id"].(string); ok {
		status.DeviceID = value
	}
	evidence, err := parseEvidence(envelope["evidence"], false)
	if err != nil {
		return RuntimeHealthStatus{}, err
	}
	status.Evidence = evidence
	return status, nil
}

// redactSenderIdentities removes remote-command sender identity fields
// (from_number, channel, reason) from a parsed health object in place so the
// Raw passthrough used by JSON output can never leak phone numbers or channel
// identities. Aggregate counts remain available through the typed
// RemoteCommandLockout field.
func redactSenderIdentities(health map[string]any) {
	lockout, ok := health["remote_command_lockout"].(map[string]any)
	if !ok {
		return
	}
	senders, ok := lockout["senders"].([]any)
	if !ok {
		return
	}
	for _, item := range senders {
		sender, ok := item.(map[string]any)
		if !ok {
			continue
		}
		delete(sender, "from_number")
		delete(sender, "channel")
		delete(sender, "reason")
	}
}

func parseEvidence(value any, requireFields bool) (EvidenceStatus, error) {
	if value == nil {
		if requireFields {
			return EvidenceStatus{}, fmt.Errorf("runtime health evidence field is not an object")
		}
		return EvidenceStatus{}, nil
	}
	m, ok := value.(map[string]any)
	if !ok {
		return EvidenceStatus{}, fmt.Errorf("runtime health evidence field is not an object")
	}
	var es EvidenceStatus
	if value, present := m["enabled"]; present {
		v, ok := value.(bool)
		if !ok {
			return EvidenceStatus{}, fmt.Errorf("runtime health evidence enabled field is not boolean")
		}
		es.Enabled = v
	} else if requireFields {
		return EvidenceStatus{}, fmt.Errorf("runtime health evidence is missing required enabled field")
	}
	if value, present := m["available"]; present {
		v, ok := value.(bool)
		if !ok {
			return EvidenceStatus{}, fmt.Errorf("runtime health evidence available field is not boolean")
		}
		es.Available = v
	} else if requireFields {
		return EvidenceStatus{}, fmt.Errorf("runtime health evidence is missing required available field")
	}
	if value, present := m["public_key_hex"]; present {
		v, ok := value.(string)
		if !ok {
			return EvidenceStatus{}, fmt.Errorf("runtime health evidence public_key_hex field is not a string")
		}
		es.PublicKeyHex = v
	} else if requireFields {
		return EvidenceStatus{}, fmt.Errorf("runtime health evidence is missing required public_key_hex field")
	}

	// Optional v2 evidence posture fields. Present fields with wrong types
	// fail closed like the required fields above.
	var err error
	if es.ArtifactVersion, err = optionalStringField(m, "artifact_version", "evidence"); err != nil {
		return EvidenceStatus{}, err
	}
	if es.ProtocolVersion, err = optionalStringField(m, "protocol_version", "evidence"); err != nil {
		return EvidenceStatus{}, err
	}
	if es.ActionEventType, err = optionalStringField(m, "action_event_type", "evidence"); err != nil {
		return EvidenceStatus{}, err
	}
	if es.ChainHeadHash, err = optionalNullableStringField(m, "chain_head_hash", "evidence"); err != nil {
		return EvidenceStatus{}, err
	}
	if es.PendingExportCount, err = optionalNullableIntField(m, "pending_export_count", "evidence"); err != nil {
		return EvidenceStatus{}, err
	}
	if es.LastAttestedActionID, err = optionalNullableIntField(m, "last_attested_action_id", "evidence"); err != nil {
		return EvidenceStatus{}, err
	}
	if es.AttestationGapCount, err = optionalIntField(m, "attestation_gap_count", "evidence"); err != nil {
		return EvidenceStatus{}, err
	}
	if es.StatusCounts, err = optionalIntMapField(m, "status_counts", "evidence"); err != nil {
		return EvidenceStatus{}, err
	}
	return es, nil
}

// parseHealthV2Blocks parses the optional nested blocks of the canonical
// runtime v2 health object. Missing blocks are left absent (nil) so doctor
// can degrade gracefully; present blocks with wrong types fail closed.
func parseHealthV2Blocks(health map[string]any, status *RuntimeHealthStatus) error {
	var err error
	if status.UptimeS, err = optionalFloatField(health, "uptime_s", "health"); err != nil {
		return err
	}
	if status.HealthSocketPath, err = optionalStringField(health, "health_socket_path", "health"); err != nil {
		return err
	}

	if block, present, blockErr := optionalBlock(health, "capability_posture"); blockErr != nil {
		return blockErr
	} else if present {
		posture, parseErr := parseCapabilityPosture(block)
		if parseErr != nil {
			return parseErr
		}
		status.CapabilityPosture = &posture
	}

	if raw, present := health["sensors"]; present {
		sensors, parseErr := parseSensors(raw)
		if parseErr != nil {
			return parseErr
		}
		status.Sensors = sensors
	}

	if block, present, blockErr := optionalBlock(health, "last_alert_timestamps"); blockErr != nil {
		return blockErr
	} else if present {
		timestamps, parseErr := parseAlertTimestamps(block)
		if parseErr != nil {
			return parseErr
		}
		status.LastAlertTimestamps = &timestamps
	}

	if block, present, blockErr := optionalBlock(health, "alert_outbox"); blockErr != nil {
		return blockErr
	} else if present {
		outbox, parseErr := parseAlertOutbox(block)
		if parseErr != nil {
			return parseErr
		}
		status.AlertOutbox = &outbox
	}

	if block, present, blockErr := optionalBlock(health, "device_policy"); blockErr != nil {
		return blockErr
	} else if present {
		policy, parseErr := parseDevicePolicy(block)
		if parseErr != nil {
			return parseErr
		}
		status.DevicePolicy = &policy
	}

	if block, present, blockErr := optionalBlock(health, "remote_command_lockout"); blockErr != nil {
		return blockErr
	} else if present {
		lockout, parseErr := parseRemoteCommandLockout(block)
		if parseErr != nil {
			return parseErr
		}
		status.RemoteCommandLockout = &lockout
	}

	if block, present, blockErr := optionalBlock(health, "gateway_broker_posture"); blockErr != nil {
		return blockErr
	} else if present {
		posture, parseErr := parseGatewayBrokerPosture(block)
		if parseErr != nil {
			return parseErr
		}
		status.GatewayBrokerPosture = &posture
	}

	if block, present, blockErr := optionalBlock(health, "state_store_encryption"); blockErr != nil {
		return blockErr
	} else if present {
		posture, parseErr := parseStateStoreEncryption(block)
		if parseErr != nil {
			return parseErr
		}
		status.StateStoreEncryption = &posture
	}

	return nil
}

func parseCapabilityPosture(m map[string]any) (CapabilityPosture, error) {
	const field = "capability_posture"
	var posture CapabilityPosture
	var err error
	if posture.Available, err = requiredBoolField(m, "available", field); err != nil {
		return posture, err
	}
	if posture.SMSAvailable, err = requiredBoolField(m, "sms_available", field); err != nil {
		return posture, err
	}
	if posture.WhatsAppAvailable, err = requiredBoolField(m, "whatsapp_available", field); err != nil {
		return posture, err
	}
	if posture.GatewayReachable, err = requiredBoolField(m, "gateway_reachable", field); err != nil {
		return posture, err
	}
	if posture.LocalSLMLoaded, err = requiredBoolField(m, "local_slm_loaded", field); err != nil {
		return posture, err
	}
	if posture.RelayConnected, err = requiredBoolField(m, "relay_connected", field); err != nil {
		return posture, err
	}
	if posture.InternetAvailable, err = requiredBoolField(m, "internet_available", field); err != nil {
		return posture, err
	}
	if posture.CheckedAtMs, err = requiredIntField(m, "checked_at_ms", field); err != nil {
		return posture, err
	}
	if posture.ExpiresAtMs, err = requiredIntField(m, "expires_at_ms", field); err != nil {
		return posture, err
	}
	if posture.GatewayLastHeartbeatMs, err = optionalNullableIntField(m, "gateway_last_heartbeat_ms", field); err != nil {
		return posture, err
	}
	return posture, nil
}

func parseSensors(raw any) ([]SensorStatus, error) {
	if raw == nil {
		return nil, fmt.Errorf("runtime health sensors field is not an array")
	}
	items, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("runtime health sensors field is not an array")
	}
	sensors := make([]SensorStatus, 0, len(items))
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("runtime health sensors[] entry is not an object")
		}
		sensor, err := parseSensor(m)
		if err != nil {
			return nil, err
		}
		sensors = append(sensors, sensor)
	}
	return sensors, nil
}

func parseSensor(m map[string]any) (SensorStatus, error) {
	const field = "sensors[]"
	var sensor SensorStatus
	var err error
	if sensor.ID, err = requiredStringField(m, "id", field); err != nil {
		return sensor, err
	}
	if sensor.Type, err = requiredStringField(m, "type", field); err != nil {
		return sensor, err
	}
	if sensor.Protocol, err = requiredStringField(m, "protocol", field); err != nil {
		return sensor, err
	}
	if sensor.PollIntervalMs, err = requiredIntField(m, "poll_interval_ms", field); err != nil {
		return sensor, err
	}
	if sensor.Connected, err = requiredBoolField(m, "connected", field); err != nil {
		return sensor, err
	}
	if sensor.LastSeenMs, err = optionalNullableIntField(m, "last_seen_ms", field); err != nil {
		return sensor, err
	}
	if sensor.Stale, err = requiredBoolField(m, "stale", field); err != nil {
		return sensor, err
	}
	return sensor, nil
}

func parseAlertTimestamps(m map[string]any) (AlertTimestamps, error) {
	const field = "last_alert_timestamps"
	var timestamps AlertTimestamps
	var err error
	if timestamps.ByChannel, err = requiredIntMapField(m, "by_channel", field); err != nil {
		return timestamps, err
	}
	if timestamps.ByTrigger, err = requiredIntMapField(m, "by_trigger", field); err != nil {
		return timestamps, err
	}
	return timestamps, nil
}

func parseAlertOutbox(m map[string]any) (AlertOutboxState, error) {
	const field = "alert_outbox"
	var outbox AlertOutboxState
	var err error
	if outbox.BacklogCount, err = requiredIntField(m, "backlog_count", field); err != nil {
		return outbox, err
	}
	if outbox.OldestQueuedOriginalTs, err = optionalNullableIntField(m, "oldest_queued_original_ts", field); err != nil {
		return outbox, err
	}
	if outbox.OldestQueuedAgeMs, err = optionalNullableIntField(m, "oldest_queued_age_ms", field); err != nil {
		return outbox, err
	}
	if outbox.RetryIntervalMinutes, err = requiredFloatField(m, "retry_interval_minutes", field); err != nil {
		return outbox, err
	}
	if outbox.MaxNonTierDAttempts, err = requiredIntField(m, "max_non_tier_d_attempts", field); err != nil {
		return outbox, err
	}
	if outbox.TierDCriticalWarningThreshold, err = requiredIntField(m, "tier_d_critical_warning_threshold", field); err != nil {
		return outbox, err
	}
	if outbox.BatchSize, err = requiredIntField(m, "batch_size", field); err != nil {
		return outbox, err
	}
	return outbox, nil
}

func parseDevicePolicy(m map[string]any) (DevicePolicyState, error) {
	const field = "device_policy"
	var policy DevicePolicyState
	var err error
	if policy.Available, err = requiredBoolField(m, "available", field); err != nil {
		return policy, err
	}
	if policy.Enabled, err = requiredBoolField(m, "enabled", field); err != nil {
		return policy, err
	}
	if policy.PolicyVersion, err = optionalNullableIntField(m, "policy_version", field); err != nil {
		return policy, err
	}
	if policy.Tier, err = optionalNullableStringField(m, "tier", field); err != nil {
		return policy, err
	}
	if policy.RelayBEnabled, err = optionalNullableBoolField(m, "relay_b_enabled", field); err != nil {
		return policy, err
	}
	if policy.RelayCEnabled, err = optionalNullableBoolField(m, "relay_c_enabled", field); err != nil {
		return policy, err
	}
	if policy.CloudLLMEnabled, err = optionalNullableBoolField(m, "cloud_llm_enabled", field); err != nil {
		return policy, err
	}
	if policy.AlertSMSMonthlyCap, err = optionalNullableIntField(m, "alert_sms_monthly_cap", field); err != nil {
		return policy, err
	}
	if policy.AlertWhatsAppMonthlyCap, err = optionalNullableIntField(m, "alert_whatsapp_monthly_cap", field); err != nil {
		return policy, err
	}
	if policy.ValidUntil, err = optionalNullableIntField(m, "valid_until", field); err != nil {
		return policy, err
	}
	if policy.IssuedAt, err = optionalNullableIntField(m, "issued_at", field); err != nil {
		return policy, err
	}
	if policy.IsExpired, err = optionalNullableBoolField(m, "is_expired", field); err != nil {
		return policy, err
	}
	return policy, nil
}

func parseRemoteCommandLockout(m map[string]any) (RemoteCommandLockoutState, error) {
	const field = "remote_command_lockout"
	var lockout RemoteCommandLockoutState
	var err error
	if lockout.EnforcementEnabled, err = requiredBoolField(m, "enforcement_enabled", field); err != nil {
		return lockout, err
	}
	if lockout.RiskWindowMs, err = requiredIntField(m, "risk_window_ms", field); err != nil {
		return lockout, err
	}
	if lockout.StaleAfterMs, err = requiredIntField(m, "stale_after_ms", field); err != nil {
		return lockout, err
	}
	if lockout.IncidentSenderLimit, err = requiredIntField(m, "incident_sender_limit", field); err != nil {
		return lockout, err
	}
	raw, present := m["senders"]
	if !present {
		return lockout, fmt.Errorf("runtime health remote_command_lockout is missing required senders field")
	}
	items, ok := raw.([]any)
	if !ok {
		return lockout, fmt.Errorf("runtime health remote_command_lockout senders field is not an array")
	}
	lockout.Senders = make([]RemoteCommandLockoutSender, 0, len(items))
	for _, item := range items {
		senderMap, ok := item.(map[string]any)
		if !ok {
			return lockout, fmt.Errorf("runtime health remote_command_lockout senders[] entry is not an object")
		}
		sender, parseErr := parseLockoutSender(senderMap)
		if parseErr != nil {
			return lockout, parseErr
		}
		lockout.Senders = append(lockout.Senders, sender)
	}
	return lockout, nil
}

func parseLockoutSender(m map[string]any) (RemoteCommandLockoutSender, error) {
	const field = "remote_command_lockout.senders[]"
	var sender RemoteCommandLockoutSender
	var err error
	if sender.Channel, err = requiredStringField(m, "channel", field); err != nil {
		return sender, err
	}
	if sender.FromNumber, err = requiredStringField(m, "from_number", field); err != nil {
		return sender, err
	}
	if sender.RiskLevel, err = requiredStringField(m, "risk_level", field); err != nil {
		return sender, err
	}
	if sender.Reason, err = requiredStringField(m, "reason", field); err != nil {
		return sender, err
	}
	if sender.LockedOut, err = requiredBoolField(m, "locked_out", field); err != nil {
		return sender, err
	}
	if sender.EnforcementEnabled, err = requiredBoolField(m, "enforcement_enabled", field); err != nil {
		return sender, err
	}
	if sender.Stale, err = requiredBoolField(m, "stale", field); err != nil {
		return sender, err
	}
	if sender.IncidentCount, err = requiredIntField(m, "incident_count", field); err != nil {
		return sender, err
	}
	if sender.RejectionCount, err = requiredIntField(m, "rejection_count", field); err != nil {
		return sender, err
	}
	if sender.WindowMs, err = requiredIntField(m, "window_ms", field); err != nil {
		return sender, err
	}
	if sender.CheckedAtMs, err = requiredIntField(m, "checked_at_ms", field); err != nil {
		return sender, err
	}
	return sender, nil
}

func parseGatewayBrokerPosture(m map[string]any) (GatewayBrokerPosture, error) {
	const field = "gateway_broker_posture"
	var posture GatewayBrokerPosture
	var err error
	if posture.Available, err = requiredBoolField(m, "available", field); err != nil {
		return posture, err
	}
	if posture.GatewayEnabled, err = requiredBoolField(m, "gateway_enabled", field); err != nil {
		return posture, err
	}
	if posture.RequireCredentials, err = requiredBoolField(m, "require_credentials", field); err != nil {
		return posture, err
	}
	if posture.CredentialsConfigured, err = requiredBoolField(m, "credentials_configured", field); err != nil {
		return posture, err
	}
	if posture.RequiresACLHardening, err = requiredBoolField(m, "requires_acl_hardening", field); err != nil {
		return posture, err
	}
	if posture.DeploymentCheck, err = requiredStringField(m, "deployment_check", field); err != nil {
		return posture, err
	}
	if posture.AnonymousAccess, err = requiredStringField(m, "anonymous_access", field); err != nil {
		return posture, err
	}
	if posture.ACLPolicy, err = requiredStringField(m, "acl_policy", field); err != nil {
		return posture, err
	}
	return posture, nil
}

func parseStateStoreEncryption(m map[string]any) (StateStoreEncryptionPosture, error) {
	const field = "state_store_encryption"
	var posture StateStoreEncryptionPosture
	var err error
	if posture.Available, err = requiredBoolField(m, "available", field); err != nil {
		return posture, err
	}
	if posture.Satisfied, err = requiredBoolField(m, "satisfied", field); err != nil {
		return posture, err
	}
	if posture.MarkerConfigured, err = requiredBoolField(m, "marker_configured", field); err != nil {
		return posture, err
	}
	if posture.PathPrefixConfigured, err = requiredBoolField(m, "path_prefix_configured", field); err != nil {
		return posture, err
	}
	if posture.Mode, err = requiredStringField(m, "mode", field); err != nil {
		return posture, err
	}
	return posture, nil
}

// optionalBlock returns the named nested object when present and non-null.
// A present non-object value fails closed like the evidence block does.
func optionalBlock(health map[string]any, key string) (map[string]any, bool, error) {
	raw, present := health[key]
	if !present || raw == nil {
		return nil, false, nil
	}
	obj, ok := raw.(map[string]any)
	if !ok {
		return nil, false, fmt.Errorf("runtime health %s field is not an object", key)
	}
	return obj, true, nil
}

func requiredBoolField(m map[string]any, key, field string) (bool, error) {
	raw, present := m[key]
	if !present {
		return false, fmt.Errorf("runtime health %s is missing required %s field", field, key)
	}
	v, ok := raw.(bool)
	if !ok {
		return false, fmt.Errorf("runtime health %s %s field is not boolean", field, key)
	}
	return v, nil
}

func requiredStringField(m map[string]any, key, field string) (string, error) {
	raw, present := m[key]
	if !present {
		return "", fmt.Errorf("runtime health %s is missing required %s field", field, key)
	}
	v, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("runtime health %s %s field is not a string", field, key)
	}
	return v, nil
}

func requiredIntField(m map[string]any, key, field string) (int64, error) {
	raw, present := m[key]
	if !present {
		return 0, fmt.Errorf("runtime health %s is missing required %s field", field, key)
	}
	return asInt(raw, field, key)
}

func requiredFloatField(m map[string]any, key, field string) (float64, error) {
	raw, present := m[key]
	if !present {
		return 0, fmt.Errorf("runtime health %s is missing required %s field", field, key)
	}
	v, ok := raw.(float64)
	if !ok {
		return 0, fmt.Errorf("runtime health %s %s field is not numeric", field, key)
	}
	return v, nil
}

func requiredIntMapField(m map[string]any, key, field string) (map[string]int64, error) {
	raw, present := m[key]
	if !present {
		return nil, fmt.Errorf("runtime health %s is missing required %s field", field, key)
	}
	return asIntMap(raw, field, key)
}

// optionalStringField returns "" when the field is absent or null.
func optionalStringField(m map[string]any, key, field string) (string, error) {
	raw, present := m[key]
	if !present || raw == nil {
		return "", nil
	}
	v, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("runtime health %s %s field is not a string", field, key)
	}
	return v, nil
}

// optionalIntField returns 0 when the field is absent or null.
func optionalIntField(m map[string]any, key, field string) (int64, error) {
	raw, present := m[key]
	if !present || raw == nil {
		return 0, nil
	}
	return asInt(raw, field, key)
}

// optionalFloatField returns 0 when the field is absent or null.
func optionalFloatField(m map[string]any, key, field string) (float64, error) {
	raw, present := m[key]
	if !present || raw == nil {
		return 0, nil
	}
	v, ok := raw.(float64)
	if !ok {
		return 0, fmt.Errorf("runtime health %s %s field is not numeric", field, key)
	}
	return v, nil
}

// optionalNullableIntField preserves the runtime's explicit null distinction.
func optionalNullableIntField(m map[string]any, key, field string) (*int64, error) {
	raw, present := m[key]
	if !present || raw == nil {
		return nil, nil
	}
	v, err := asInt(raw, field, key)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func optionalNullableBoolField(m map[string]any, key, field string) (*bool, error) {
	raw, present := m[key]
	if !present || raw == nil {
		return nil, nil
	}
	v, ok := raw.(bool)
	if !ok {
		return nil, fmt.Errorf("runtime health %s %s field is not boolean", field, key)
	}
	return &v, nil
}

func optionalNullableStringField(m map[string]any, key, field string) (*string, error) {
	raw, present := m[key]
	if !present || raw == nil {
		return nil, nil
	}
	v, ok := raw.(string)
	if !ok {
		return nil, fmt.Errorf("runtime health %s %s field is not a string", field, key)
	}
	return &v, nil
}

func optionalIntMapField(m map[string]any, key, field string) (map[string]int64, error) {
	raw, present := m[key]
	if !present || raw == nil {
		return nil, nil
	}
	return asIntMap(raw, field, key)
}

func asInt(raw any, field, key string) (int64, error) {
	v, ok := raw.(float64)
	if !ok {
		return 0, fmt.Errorf("runtime health %s %s field is not an integer", field, key)
	}
	if math.Trunc(v) != v {
		return 0, fmt.Errorf("runtime health %s %s field is not an integer", field, key)
	}
	return int64(v), nil
}

func asIntMap(raw any, field, key string) (map[string]int64, error) {
	obj, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("runtime health %s %s field is not an object", field, key)
	}
	result := make(map[string]int64, len(obj))
	for k, v := range obj {
		value, err := asInt(v, field, key+"."+k)
		if err != nil {
			return nil, err
		}
		result[k] = value
	}
	return result, nil
}
