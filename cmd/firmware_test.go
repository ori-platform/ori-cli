// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/ori-platform/ori-cli/internal/rpc"
)

type firmwareMQTTCall struct {
	socketPath string
	request    rpc.FirmwareMQTTRequest
}

type recordingFirmwareMQTT struct {
	calls    []firmwareMQTTCall
	response rpc.FirmwareMQTTResponse
	err      error
}

func (r *recordingFirmwareMQTT) Run(
	_ context.Context,
	socketPath string,
	request rpc.FirmwareMQTTRequest,
) (rpc.FirmwareMQTTResponse, error) {
	r.calls = append(r.calls, firmwareMQTTCall{socketPath: socketPath, request: request})
	return r.response, r.err
}

func firmwareMQTTSuccess(result string) rpc.FirmwareMQTTResponse {
	return rpc.FirmwareMQTTResponse{
		Contract:      rpc.FirmwareMQTTContract,
		SchemaVersion: rpc.FirmwareMQTTSchemaVersion,
		OK:            true,
		Result:        json.RawMessage(result),
	}
}

func assertFirmwareMQTTDelegates(
	t *testing.T,
	args []string,
	wantRequest rpc.FirmwareMQTTRequest,
) {
	t.Helper()
	result := `{"operation":"` + wantRequest.Operation + `","correlation_id":"corr"}`
	if strings.HasPrefix(wantRequest.Operation, "verify_") {
		result = `{"operation":"` + wantRequest.Operation +
			`","correlation_id":"corr","verdict":"accepted","successful":true}`
	}
	fake := &recordingFirmwareMQTT{response: firmwareMQTTSuccess(result)}
	args = append(args, "--socket", "/tmp/ori-firmware-mqtt.sock")
	code, _, stderr := runWithOptions(args, Options{FirmwareMQTT: fake.Run})
	if code != 0 {
		t.Fatalf("expected success, got code=%d stderr=%q", code, stderr)
	}
	if len(fake.calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(fake.calls))
	}
	if fake.calls[0].socketPath != "/tmp/ori-firmware-mqtt.sock" {
		t.Fatalf("socket = %q", fake.calls[0].socketPath)
	}
	if !reflect.DeepEqual(fake.calls[0].request, wantRequest) {
		t.Fatalf("request = %#v, want %#v", fake.calls[0].request, wantRequest)
	}
	encoded, err := json.Marshal(fake.calls[0].request)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	if strings.Contains(string(encoded), "actor") {
		t.Fatalf("CLI forwarded forbidden actor field: %s", encoded)
	}
}

func TestFirmwareMQTTCsrRequestDelegatesToRuntime(t *testing.T) {
	assertFirmwareMQTTDelegates(
		t,
		[]string{
			"firmware", "mqtt", "create-csr",
			"--device-id", "edge-01",
			"--reason", "initial certificate",
		},
		rpc.FirmwareMQTTRequest{
			Contract:      rpc.FirmwareMQTTContract,
			SchemaVersion: rpc.FirmwareMQTTSchemaVersion,
			Operation:     "create_csr",
			DeviceID:      "edge-01",
			Reason:        "initial certificate",
		},
	)
}

func TestFirmwareMQTTRevokeDelegatesToRuntime(t *testing.T) {
	assertFirmwareMQTTDelegates(
		t,
		[]string{
			"firmware", "mqtt", "revoke",
			"--device-id", "edge-01",
			"--reason", "certificate compromised",
		},
		rpc.FirmwareMQTTRequest{
			Contract:      rpc.FirmwareMQTTContract,
			SchemaVersion: rpc.FirmwareMQTTSchemaVersion,
			Operation:     "revoke",
			DeviceID:      "edge-01",
			Reason:        "certificate compromised",
		},
	)
}

func TestFirmwareMQTTStatusDelegatesToRuntime(t *testing.T) {
	assertFirmwareMQTTDelegates(
		t,
		[]string{
			"firmware", "mqtt", "status",
			"--device-id", "edge-01",
			"--request-id", "fleet-check-01",
		},
		rpc.FirmwareMQTTRequest{
			Contract:      rpc.FirmwareMQTTContract,
			SchemaVersion: rpc.FirmwareMQTTSchemaVersion,
			Operation:     "status",
			DeviceID:      "edge-01",
			RequestID:     "fleet-check-01",
		},
	)
}

func TestFirmwareMQTTOperationsDelegateToRuntime(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		wantRequest rpc.FirmwareMQTTRequest
	}{
		{
			name: "prepare install",
			args: []string{
				"firmware", "mqtt", "prepare-install",
				"--correlation-id", "corr-01",
				"--response-b64", "Y3Ny",
				"--reason", "issue certificate",
			},
			wantRequest: rpc.FirmwareMQTTRequest{
				Contract:      rpc.FirmwareMQTTContract,
				SchemaVersion: rpc.FirmwareMQTTSchemaVersion,
				Operation:     "prepare_install",
				CorrelationID: "corr-01",
				ResponseB64:   "Y3Ny",
				Reason:        "issue certificate",
			},
		},
		{
			name: "verify install",
			args: []string{
				"firmware", "mqtt", "verify-install-result",
				"--correlation-id", "corr-02",
				"--response-b64", "cmVzdWx0",
			},
			wantRequest: rpc.FirmwareMQTTRequest{
				Contract:      rpc.FirmwareMQTTContract,
				SchemaVersion: rpc.FirmwareMQTTSchemaVersion,
				Operation:     "verify_install_result",
				CorrelationID: "corr-02",
				ResponseB64:   "cmVzdWx0",
			},
		},
		{
			name: "verify revoke",
			args: []string{
				"firmware", "mqtt", "verify-revoke-result",
				"--correlation-id", "corr-03",
				"--response-b64", "cmVzdWx0",
			},
			wantRequest: rpc.FirmwareMQTTRequest{
				Contract:      rpc.FirmwareMQTTContract,
				SchemaVersion: rpc.FirmwareMQTTSchemaVersion,
				Operation:     "verify_revoke_result",
				CorrelationID: "corr-03",
				ResponseB64:   "cmVzdWx0",
			},
		},
		{
			name: "verify status",
			args: []string{
				"firmware", "mqtt", "verify-status-response",
				"--correlation-id", "corr-04",
				"--response-b64", "c3RhdHVz",
			},
			wantRequest: rpc.FirmwareMQTTRequest{
				Contract:      rpc.FirmwareMQTTContract,
				SchemaVersion: rpc.FirmwareMQTTSchemaVersion,
				Operation:     "verify_status_response",
				CorrelationID: "corr-04",
				ResponseB64:   "c3RhdHVz",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertFirmwareMQTTDelegates(t, test.args, test.wantRequest)
		})
	}
}

func TestFirmwareMQTTPrepareInstallRendersPublicArtifactsOnly(t *testing.T) {
	fake := &recordingFirmwareMQTT{
		response: firmwareMQTTSuccess(
			`{"correlation_id":"corr-01","operation":"prepare_install","provision_seq":42,` +
				`"certificate":{"sha256":"abcd","serial_number":"17",` +
				`"not_valid_before":"2026-01-01T00:00:00Z","not_valid_after":"2027-01-01T00:00:00Z"}}`,
		),
	}
	code, stdout, stderr := runWithOptions(
		[]string{
			"--json", "firmware", "mqtt", "prepare-install",
			"--correlation-id", "corr-01",
			"--response-b64", "Y3Ny",
			"--reason", "issue certificate",
		},
		Options{FirmwareMQTT: fake.Run},
	)
	if code != 0 {
		t.Fatalf("expected success, got code=%d stderr=%q", code, stderr)
	}
	var response map[string]any
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatalf("decode stdout: %v\n%s", err, stdout)
	}
	if response["contract"] != rpc.FirmwareMQTTContract {
		t.Fatalf("contract = %#v", response["contract"])
	}
	result, ok := response["result"].(map[string]any)
	if !ok {
		t.Fatalf("result = %#v", response["result"])
	}
	if result["provision_seq"] != float64(42) {
		t.Fatalf("provision_seq = %#v", result["provision_seq"])
	}
	if strings.Contains(stdout, "\x1b[") {
		t.Fatalf("JSON output contains ANSI escapes: %q", stdout)
	}

	code, stdout, stderr = runWithOptions(
		[]string{
			"firmware", "mqtt", "prepare-install",
			"--correlation-id", "corr-01",
			"--response-b64", "Y3Ny",
			"--reason", "issue certificate",
		},
		Options{FirmwareMQTT: fake.Run},
	)
	if code != 0 {
		t.Fatalf("expected text success, got code=%d stderr=%q", code, stderr)
	}
	wantCertificate := `certificate: {"not_valid_after":"2027-01-01T00:00:00Z",` +
		`"not_valid_before":"2026-01-01T00:00:00Z","serial_number":"17","sha256":"abcd"}`
	if !strings.Contains(stdout, wantCertificate) {
		t.Fatalf("certificate metadata is not deterministic:\n%s", stdout)
	}
}

func TestFirmwareMQTTJSONOutput(t *testing.T) {
	fake := &recordingFirmwareMQTT{
		response: firmwareMQTTSuccess(
			`{"correlation_id":"corr-01","operation":"create_csr","provision_seq":42}`,
		),
	}
	code, stdout, stderr := runWithOptions(
		[]string{
			"--json", "firmware", "mqtt", "create-csr",
			"--device-id", "edge-01",
			"--reason", "rotate",
		},
		Options{FirmwareMQTT: fake.Run},
	)
	if code != 0 {
		t.Fatalf("expected success, got code=%d stderr=%q", code, stderr)
	}
	if !json.Valid([]byte(stdout)) || strings.Contains(stdout, "\x1b[") {
		t.Fatalf("invalid machine output: %q", stdout)
	}
}

func TestFirmwareMQTTTypedRuntimeFailureIsMachineReadableAndNonzero(t *testing.T) {
	fake := &recordingFirmwareMQTT{
		response: rpc.FirmwareMQTTResponse{
			Contract:      rpc.FirmwareMQTTContract,
			SchemaVersion: rpc.FirmwareMQTTSchemaVersion,
			OK:            false,
			Error: &rpc.FirmwareMQTTError{
				Code:   "anchor_not_confirmed",
				Detail: "evidence store has not confirmed this anchor epoch",
			},
		},
	}
	code, stdout, stderr := runWithOptions(
		[]string{
			"--json", "firmware", "mqtt", "create-csr",
			"--device-id", "edge-01",
			"--reason", "rotate",
		},
		Options{FirmwareMQTT: fake.Run},
	)
	if code == 0 {
		t.Fatal("expected nonzero exit")
	}
	if stderr != "" {
		t.Fatalf("expected no duplicate stderr payload, got %q", stderr)
	}
	if !strings.Contains(stdout, `"code": "anchor_not_confirmed"`) ||
		!strings.Contains(stdout, `"ok": false`) {
		t.Fatalf("typed failure not preserved: %s", stdout)
	}
}

func TestFirmwareMQTTRuntimeUnavailable(t *testing.T) {
	fake := &recordingFirmwareMQTT{err: errors.New("connect: no such file")}
	code, _, stderr := runWithOptions(
		[]string{
			"firmware", "mqtt", "status",
			"--device-id", "edge-01",
			"--request-id", "request-01",
		},
		Options{FirmwareMQTT: fake.Run},
	)
	if code == 0 {
		t.Fatal("expected nonzero exit")
	}
	if !strings.Contains(stderr, "runtime firmware MQTT service unavailable") {
		t.Fatalf("stderr = %q", stderr)
	}
}

func TestFirmwareMQTTInstallResultRequiresAcceptedVerdict(t *testing.T) {
	for _, verdict := range []string{"refused", "invalid_material"} {
		t.Run(verdict, func(t *testing.T) {
			fake := &recordingFirmwareMQTT{
				response: firmwareMQTTSuccess(
					`{"correlation_id":"corr-01","device_id":"edge-01",` +
						`"operation":"verify_install_result","verdict":"` + verdict + `",` +
						`"response":{},"successful":false}`,
				),
			}
			code, stdout, stderr := runWithOptions(
				[]string{
					"--json", "firmware", "mqtt", "verify-install-result",
					"--correlation-id", "corr-01",
					"--response-b64", "cmVzdWx0",
				},
				Options{FirmwareMQTT: fake.Run},
			)
			if code == 0 {
				t.Fatal("expected nonzero exit")
			}
			if stderr != "" {
				t.Fatalf("unexpected stderr: %q", stderr)
			}
			if !strings.Contains(stdout, `"successful": false`) ||
				!strings.Contains(stdout, `"verdict": "`+verdict+`"`) {
				t.Fatalf("stdout = %s", stdout)
			}
		})
	}
}

func TestFirmwareMQTTVerifiedMutationAcceptsExactAcceptedVerdict(t *testing.T) {
	fake := &recordingFirmwareMQTT{
		response: firmwareMQTTSuccess(
			`{"correlation_id":"corr-01","device_id":"edge-01",` +
				`"operation":"verify_revoke_result","verdict":"accepted",` +
				`"response":{},"successful":true}`,
		),
	}
	code, stdout, stderr := runWithOptions(
		[]string{
			"firmware", "mqtt", "verify-revoke-result",
			"--correlation-id", "corr-01",
			"--response-b64", "cmVzdWx0",
		},
		Options{FirmwareMQTT: fake.Run},
	)
	if code != 0 {
		t.Fatalf("expected success, got code=%d stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, "accepted") {
		t.Fatalf("stdout = %q", stdout)
	}
}

func TestFirmwareMQTTNeverForwardsPrivateKeys(t *testing.T) {
	forwardingFake := &recordingFirmwareMQTT{
		response: firmwareMQTTSuccess(`{"operation":"create_csr"}`),
	}
	code, _, stderr := runWithOptions(
		[]string{
			"firmware", "mqtt", "create-csr",
			"--device-id", "edge-01",
			"--reason", "issue",
		},
		Options{FirmwareMQTT: forwardingFake.Run},
	)
	if code != 0 {
		t.Fatalf("expected success, got code=%d stderr=%q", code, stderr)
	}
	encoded, err := json.Marshal(forwardingFake.calls[0].request)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	for _, forbidden := range []string{"actor", "private", "seed", "ca_key"} {
		if strings.Contains(strings.ToLower(string(encoded)), forbidden) {
			t.Fatalf("CLI request forwarded %q: %s", forbidden, encoded)
		}
	}

	tests := []string{
		`{"operation":"prepare_install","private_key":"secret"}`,
		`{"operation":"prepare_install","material":"-----BEGIN PRIVATE KEY-----"}`,
		`{"operation":"prepare_install","seed_b64":"secret"}`,
	}
	for _, result := range tests {
		fake := &recordingFirmwareMQTT{response: firmwareMQTTSuccess(result)}
		code, _, stderr := runWithOptions(
			[]string{
				"firmware", "mqtt", "prepare-install",
				"--correlation-id", "corr-01",
				"--response-b64", "Y3Ny",
				"--reason", "issue",
			},
			Options{FirmwareMQTT: fake.Run},
		)
		if code == 0 || !strings.Contains(stderr, "forbidden private material") {
			t.Fatalf("result=%s code=%d stderr=%q", result, code, stderr)
		}
	}
}

func TestFirmwareMQTTRequiredFlagsFailBeforeRuntimeCall(t *testing.T) {
	fake := &recordingFirmwareMQTT{
		response: firmwareMQTTSuccess(`{"operation":"create_csr"}`),
	}
	code, _, stderr := runWithOptions(
		[]string{"firmware", "mqtt", "create-csr", "--device-id", "edge-01"},
		Options{FirmwareMQTT: fake.Run},
	)
	if code == 0 {
		t.Fatal("expected missing reason to fail")
	}
	if !strings.Contains(stderr, `required flag(s) "reason"`) {
		t.Fatalf("stderr = %q", stderr)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("runtime called %d times", len(fake.calls))
	}
}

func TestFirmwareMQTTHelpStatesAuthorityBoundary(t *testing.T) {
	code, stdout, stderr := runWithOptions(
		[]string{"firmware", "mqtt", "--help"},
		Options{},
	)
	if code != 0 {
		t.Fatalf("expected success, got code=%d stderr=%q", code, stderr)
	}
	for _, phrase := range []string{
		"transport defence in depth",
		"does not grant Layer 1",
		"Tier B/C/D",
		"never owns issuer or",
	} {
		if !strings.Contains(stdout, phrase) {
			t.Fatalf("help missing %q:\n%s", phrase, stdout)
		}
	}
}
