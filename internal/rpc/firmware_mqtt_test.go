// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestParseFirmwareMQTTResponseAcceptsSuccess(t *testing.T) {
	response, err := ParseFirmwareMQTTResponse([]byte(
		`{"contract":"ori.runtime.firmware-mqtt-operator","schema_version":1,"ok":true,"result":{"operation":"create_csr"}}`,
	))
	if err != nil {
		t.Fatalf("parse success response: %v", err)
	}
	if !response.OK {
		t.Fatal("expected successful response")
	}
}

func TestParseFirmwareMQTTResponsePreservesTypedFailure(t *testing.T) {
	response, err := ParseFirmwareMQTTResponse([]byte(
		`{"contract":"ori.runtime.firmware-mqtt-operator","schema_version":1,"ok":false,"error":{"code":"anchor_unknown","detail":"device has no approved anchor"}}`,
	))
	if err != nil {
		t.Fatalf("parse failure response: %v", err)
	}
	if response.Error == nil || response.Error.Code != "anchor_unknown" {
		t.Fatalf("typed error = %#v", response.Error)
	}
}

func TestParseFirmwareMQTTResponseRejectsProtocolDrift(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		want    string
	}{
		{
			name:    "contract",
			payload: `{"contract":"private.operator","schema_version":1,"ok":true,"result":{}}`,
			want:    "contract mismatch",
		},
		{
			name:    "version",
			payload: `{"contract":"ori.runtime.firmware-mqtt-operator","schema_version":2,"ok":true,"result":{}}`,
			want:    "schema_version mismatch",
		},
		{
			name:    "unknown field",
			payload: `{"contract":"ori.runtime.firmware-mqtt-operator","schema_version":1,"ok":true,"result":{},"actor":"uid-0"}`,
			want:    "unknown field",
		},
		{
			name:    "duplicate field",
			payload: `{"contract":"ori.runtime.firmware-mqtt-operator","schema_version":1,"ok":true,"ok":false,"result":{}}`,
			want:    "duplicate field",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseFirmwareMQTTResponse([]byte(test.payload))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestFirmwareMQTTContractVersionMismatch(t *testing.T) {
	_, err := ParseFirmwareMQTTResponse([]byte(
		`{"contract":"ori.runtime.firmware-mqtt-operator","schema_version":2,"ok":true,"result":{}}`,
	))
	if err == nil || !strings.Contains(err.Error(), "schema_version mismatch") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseFirmwareMQTTResponseRejectsInconsistentEnvelope(t *testing.T) {
	tests := []string{
		`{"contract":"ori.runtime.firmware-mqtt-operator","schema_version":1,"ok":true,"error":{"code":"internal_error","detail":"no"}}`,
		`{"contract":"ori.runtime.firmware-mqtt-operator","schema_version":1,"ok":false,"result":{},"error":{"code":"internal_error","detail":"no"}}`,
		`{"contract":"ori.runtime.firmware-mqtt-operator","schema_version":1,"ok":false,"error":{"code":"","detail":"no"}}`,
	}
	for _, payload := range tests {
		if _, err := ParseFirmwareMQTTResponse([]byte(payload)); err == nil {
			t.Fatalf("expected refusal for %s", payload)
		}
	}
}

func TestCallFirmwareMQTTSendsOneStrictRequest(t *testing.T) {
	socketFile, err := os.CreateTemp("/tmp", "ori-mqtt-*.sock")
	if err != nil {
		t.Fatalf("reserve socket path: %v", err)
	}
	socketPath := socketFile.Name()
	if err := socketFile.Close(); err != nil {
		t.Fatalf("close socket path placeholder: %v", err)
	}
	if err := os.Remove(socketPath); err != nil {
		t.Fatalf("remove socket path placeholder: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Remove(socketPath)
	})
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	requests := make(chan FirmwareMQTTRequest, 1)
	serverErrors := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverErrors <- acceptErr
			return
		}
		defer conn.Close()
		decoder := json.NewDecoder(conn)
		var request FirmwareMQTTRequest
		if decodeErr := decoder.Decode(&request); decodeErr != nil {
			serverErrors <- decodeErr
			return
		}
		requests <- request
		_, writeErr := io.WriteString(
			conn,
			`{"contract":"ori.runtime.firmware-mqtt-operator","schema_version":1,"ok":true,"result":{"operation":"create_csr"}}`+"\n",
		)
		serverErrors <- writeErr
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	request := NewFirmwareMQTTRequest("create_csr")
	request.DeviceID = "edge-01"
	request.Reason = "rotate transport identity"
	response, err := CallFirmwareMQTT(ctx, socketPath, request)
	if err != nil {
		t.Fatalf("call firmware MQTT: %v", err)
	}
	if !response.OK {
		t.Fatal("expected successful response")
	}
	if err := <-serverErrors; err != nil {
		t.Fatalf("server: %v", err)
	}
	got := <-requests
	if got.DeviceID != "edge-01" || got.Reason != "rotate transport identity" {
		t.Fatalf("request = %#v", got)
	}
}

func TestReadFirmwareMQTTReplyRejectsFramingViolations(t *testing.T) {
	tests := []struct {
		name  string
		reply string
		want  string
	}{
		{name: "missing newline", reply: `{}`, want: "newline-terminated"},
		{name: "multiple replies", reply: "{}\n{}\n", want: "more than one response"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := readFirmwareMQTTReply(strings.NewReader(test.reply))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestReadFirmwareMQTTReplyRejectsOversize(t *testing.T) {
	reply := strings.Repeat("x", firmwareMQTTReplyMaxBytes) + "\n"
	_, err := readFirmwareMQTTReply(strings.NewReader(reply))
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("error = %v", err)
	}
}

func TestCallFirmwareMQTTRejectsInvalidClientInput(t *testing.T) {
	request := NewFirmwareMQTTRequest("status")
	tests := []struct {
		name       string
		socketPath string
		mutate     func(*FirmwareMQTTRequest)
		want       string
	}{
		{name: "relative socket", socketPath: "operator.sock", mutate: func(*FirmwareMQTTRequest) {}, want: "absolute"},
		{name: "wrong contract", socketPath: "/unused", mutate: func(request *FirmwareMQTTRequest) {
			request.Contract = "wrong"
		}, want: "contract"},
		{name: "wrong schema", socketPath: "/unused", mutate: func(request *FirmwareMQTTRequest) {
			request.SchemaVersion = 2
		}, want: "schema_version"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := request
			test.mutate(&candidate)
			_, err := CallFirmwareMQTT(context.Background(), test.socketPath, candidate)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestCallFirmwareMQTTUnavailable(t *testing.T) {
	request := NewFirmwareMQTTRequest("status")
	_, err := CallFirmwareMQTT(context.Background(), "/nonexistent/ori/operator.sock", request)
	if err == nil {
		t.Fatal("expected unavailable socket error")
	}
	if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "connect") {
		t.Fatalf("unexpected error: %v", err)
	}
}
