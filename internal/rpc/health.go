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

type RuntimeHealthStatus struct {
	Status   string         `json:"status,omitempty"`
	DeviceID string         `json:"device_id,omitempty"`
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

func ParseHealth(payload []byte) (RuntimeHealthStatus, error) {
	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		return RuntimeHealthStatus{}, fmt.Errorf("decode runtime health JSON: %w", err)
	}
	status := RuntimeHealthStatus{Raw: raw}
	if value, ok := raw["status"].(string); ok {
		status.Status = value
	}
	if value, ok := raw["device_id"].(string); ok {
		status.DeviceID = value
	}
	return status, nil
}
