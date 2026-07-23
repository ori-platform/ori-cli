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
// evidence layer signing state on the device.
type EvidenceStatus struct {
	Enabled      bool   `json:"enabled"`
	Available    bool   `json:"available"`
	PublicKeyHex string `json:"public_key_hex"`
}

type RuntimeHealthStatus struct {
	Status    string         `json:"status,omitempty"`
	DeviceID  string         `json:"device_id,omitempty"`
	Evidence  EvidenceStatus `json:"evidence,omitempty"`
	Canonical bool           `json:"-"`
	Raw       map[string]any `json:"-"`
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
		return status, nil
	}

	// Legacy flat response without an envelope wrapper.
	status := RuntimeHealthStatus{Raw: envelope}
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
	return es, nil
}
