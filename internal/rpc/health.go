// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package rpc

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
)

const DefaultHealthSocket = "/run/ori/health.sock"

// EvidenceStatus is the runtime health evidence block that describes the
// Verity chain signing state on the device.
type EvidenceStatus struct {
	Enabled      bool   `json:"enabled"`
	Available    bool   `json:"available"`
	PublicKeyHex string `json:"public_key_hex"`
}

type RuntimeHealthStatus struct {
	Status   string         `json:"status,omitempty"`
	DeviceID string         `json:"device_id,omitempty"`
	Evidence EvidenceStatus `json:"evidence,omitempty"`
	Raw      map[string]any `json:"-"`
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
// also accepts the legacy flat form {"status":"ok","device_id":"..."} when no
// "ok" envelope field is present.
func ParseHealth(payload []byte) (RuntimeHealthStatus, error) {
	var envelope map[string]any
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return RuntimeHealthStatus{}, fmt.Errorf("decode runtime health JSON: %w", err)
	}

	// Reject explicit envelope failures from the runtime.
	if ok, present := envelope["ok"].(bool); present && !ok {
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

	// Canonical runtime response is wrapped in {"schema_version":1,"ok":true,"health":{...}}.
	var raw map[string]any
	if health, ok := envelope["health"].(map[string]any); ok {
		raw = health
	} else {
		raw = envelope
	}

	status := RuntimeHealthStatus{Raw: envelope}
	if value, ok := raw["status"].(string); ok {
		status.Status = value
	}
	if value, ok := raw["device_id"].(string); ok {
		status.DeviceID = value
	}
	status.Evidence = parseEvidence(raw["evidence"])
	return status, nil
}

func parseEvidence(value any) EvidenceStatus {
	m, ok := value.(map[string]any)
	if !ok {
		return EvidenceStatus{}
	}
	var es EvidenceStatus
	if v, ok := m["enabled"].(bool); ok {
		es.Enabled = v
	}
	if v, ok := m["available"].(bool); ok {
		es.Available = v
	}
	if v, ok := m["public_key_hex"].(string); ok {
		es.PublicKeyHex = v
	}
	return es
}
