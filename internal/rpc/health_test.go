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
