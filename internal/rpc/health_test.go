// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package rpc

import (
	"context"
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
