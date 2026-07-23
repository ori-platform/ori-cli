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
}

func TestParseHealthHandlesMissingEvidence(t *testing.T) {
	payload := []byte(`{"schema_version":1,"ok":true,"health":{"device_id":"edge-4"}}` + "\n")
	got, err := ParseHealth(payload)
	if err != nil {
		t.Fatalf("ParseHealth: %v", err)
	}
	if got.DeviceID != "edge-4" {
		t.Fatalf("DeviceID = %q, want edge-4", got.DeviceID)
	}
	if got.Evidence.PublicKeyHex != "" {
		t.Fatalf("expected empty evidence public key, got %q", got.Evidence.PublicKeyHex)
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
