// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ori-platform/ori-cli/internal/cloud"
	"github.com/ori-platform/ori-cli/internal/deploy"
	"github.com/ori-platform/ori-cli/internal/rpc"
)

func healthyStatus(deviceID string, evidencePub string) func(context.Context, string) (rpc.RuntimeHealthStatus, error) {
	return func(_ context.Context, _ string) (rpc.RuntimeHealthStatus, error) {
		return rpc.RuntimeHealthStatus{
			DeviceID: deviceID,
			Evidence: rpc.EvidenceStatus{
				Enabled:      evidencePub != "",
				Available:    evidencePub != "",
				PublicKeyHex: evidencePub,
			},
		}, nil
	}
}

func TestDeployGeneratesKeypair(t *testing.T) {
	dir := t.TempDir()
	getHealth := healthyStatus("edge-1", "")
	code, stdout, stderr := runWithOptions([]string{"deploy", "--key-dir", dir}, Options{GetHealth: getHealth})
	if code != 0 {
		t.Fatalf("expected success, got code=%d stderr=%q", code, stderr)
	}

	privPath := filepath.Join(dir, deploy.PrivateKeyFile)
	pubPath := filepath.Join(dir, deploy.PublicKeyFile)

	if _, err := os.Stat(privPath); err != nil {
		t.Fatalf("private key not created: %v", err)
	}
	if _, err := os.Stat(pubPath); err != nil {
		t.Fatalf("public key not created: %v", err)
	}

	if !strings.Contains(stdout, "Device identity keypair generated") {
		t.Fatalf("expected success message, got stdout=%q", stdout)
	}
	if !strings.Contains(stdout, "Device ID: edge-1") {
		t.Fatalf("expected device ID in stdout, got %q", stdout)
	}
	if !strings.Contains(stdout, "Identity public key:") {
		t.Fatalf("expected public key in stdout, got %q", stdout)
	}
	if strings.Contains(stdout, "PRIVATE KEY") || strings.Contains(stdout, "BEGIN") {
		t.Fatal("stdout must not contain private key material")
	}
}

func TestDeployReadsEvidenceAnchor(t *testing.T) {
	dir := t.TempDir()
	getHealth := healthyStatus("edge-2", "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233")
	code, stdout, stderr := runWithOptions([]string{"deploy", "--key-dir", dir}, Options{GetHealth: getHealth})
	if code != 0 {
		t.Fatalf("expected success, got code=%d stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, "Evidence public key:") {
		t.Fatalf("expected evidence public key in stdout, got %q", stdout)
	}
	if !strings.Contains(stdout, "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233") {
		t.Fatalf("expected evidence hex in stdout, got %q", stdout)
	}
}

func TestDeployFailsWhenEvidenceEnabledButAnchorMissing(t *testing.T) {
	dir := t.TempDir()
	getHealth := func(_ context.Context, _ string) (rpc.RuntimeHealthStatus, error) {
		return rpc.RuntimeHealthStatus{
			DeviceID: "edge-3",
			Evidence: rpc.EvidenceStatus{Enabled: true, Available: false, PublicKeyHex: ""},
		}, nil
	}
	code, _, _ := runWithOptions([]string{"deploy", "--key-dir", dir}, Options{GetHealth: getHealth})
	if code == 0 {
		t.Fatal("expected failure when evidence enabled but anchor missing")
	}
}

func TestDeployDryRunNoFiles(t *testing.T) {
	dir := t.TempDir()
	code, stdout, stderr := runWithOptions([]string{"deploy", "--dry-run", "--key-dir", dir}, Options{})
	if code != 0 {
		t.Fatalf("expected success, got code=%d stderr=%q", code, stderr)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected no files written in dry-run, got %d", len(entries))
	}

	if !strings.Contains(stdout, "Dry-run") {
		t.Fatalf("expected dry-run message, got stdout=%q", stdout)
	}
	if !strings.Contains(stdout, "Identity public key:") {
		t.Fatalf("expected public key in stdout, got %q", stdout)
	}
}

func TestDeployRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	getHealth := healthyStatus("edge-1", "")
	code, _, _ := runWithOptions([]string{"deploy", "--key-dir", dir}, Options{GetHealth: getHealth})
	if code != 0 {
		t.Fatalf("first deploy failed with code=%d", code)
	}

	code, _, stderr := runWithOptions([]string{"deploy", "--key-dir", dir}, Options{GetHealth: getHealth})
	if code == 0 {
		t.Fatal("expected second deploy to fail without --force")
	}
	if !strings.Contains(stderr, "--force") {
		t.Fatalf("expected --force hint in stderr, got %q", stderr)
	}
}

func TestDeployForceOverwrites(t *testing.T) {
	dir := t.TempDir()
	getHealth := healthyStatus("edge-1", "")
	code, _, _ := runWithOptions([]string{"deploy", "--key-dir", dir}, Options{GetHealth: getHealth})
	if code != 0 {
		t.Fatalf("first deploy failed with code=%d", code)
	}

	firstPub, err := os.ReadFile(filepath.Join(dir, deploy.PublicKeyFile))
	if err != nil {
		t.Fatalf("read first public key: %v", err)
	}

	code, _, stderr := runWithOptions([]string{"deploy", "--key-dir", dir, "--force"}, Options{GetHealth: getHealth})
	if code != 0 {
		t.Fatalf("force deploy failed with code=%d stderr=%q", code, stderr)
	}

	secondPub, err := os.ReadFile(filepath.Join(dir, deploy.PublicKeyFile))
	if err != nil {
		t.Fatalf("read second public key: %v", err)
	}

	if string(firstPub) == string(secondPub) {
		t.Fatal("expected new keypair after force overwrite")
	}
}

func TestDeployJSONOutput(t *testing.T) {
	dir := t.TempDir()
	getHealth := healthyStatus("edge-json", "0011")
	code, stdout, stderr := runWithOptions([]string{"--json", "deploy", "--key-dir", dir}, Options{GetHealth: getHealth})
	if code != 0 {
		t.Fatalf("expected success, got code=%d stderr=%q", code, stderr)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\noutput: %s", err, stdout)
	}
	if payload["ok"] != true {
		t.Fatalf("expected ok=true, got %v", payload["ok"])
	}
	if payload["dry_run"] != false {
		t.Fatalf("expected dry_run=false, got %v", payload["dry_run"])
	}
	if payload["device_id"] != "edge-json" {
		t.Fatalf("expected device_id=edge-json, got %v", payload["device_id"])
	}
	pubHex, ok := payload["identity_pubkey_hex"].(string)
	if !ok || len(pubHex) != 64 {
		t.Fatalf("expected 64-char identity_pubkey_hex, got %v", payload["identity_pubkey_hex"])
	}
	if payload["evidence_pubkey_hex"] != "0011" {
		t.Fatalf("expected evidence_pubkey_hex=0011, got %v", payload["evidence_pubkey_hex"])
	}
	if payload["cloud_registered"] != false {
		t.Fatalf("expected cloud_registered=false, got %v", payload["cloud_registered"])
	}
}

func TestDeployDryRunJSONOutput(t *testing.T) {
	dir := t.TempDir()
	code, stdout, stderr := runWithOptions([]string{"--json", "deploy", "--dry-run", "--key-dir", dir}, Options{})
	if code != 0 {
		t.Fatalf("expected success, got code=%d stderr=%q", code, stderr)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\noutput: %s", err, stdout)
	}
	if payload["ok"] != true {
		t.Fatalf("expected ok=true, got %v", payload["ok"])
	}
	if payload["dry_run"] != true {
		t.Fatalf("expected dry_run=true, got %v", payload["dry_run"])
	}
	pubHex, ok := payload["identity_pubkey_hex"].(string)
	if !ok || len(pubHex) != 64 {
		t.Fatalf("expected 64-char identity_pubkey_hex, got %v", payload["identity_pubkey_hex"])
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected no files in dry-run, got %d", len(entries))
	}
}

func TestDeployHealthUnavailable(t *testing.T) {
	dir := t.TempDir()
	getHealth := func(_ context.Context, _ string) (rpc.RuntimeHealthStatus, error) {
		return rpc.RuntimeHealthStatus{}, errors.New("connection refused")
	}
	code, _, stderr := runWithOptions([]string{"deploy", "--key-dir", dir}, Options{GetHealth: getHealth})
	if code == 0 {
		t.Fatal("expected failure when health unavailable")
	}
	if !strings.Contains(stderr, "runtime health unavailable") {
		t.Fatalf("expected health unavailable error, got stderr=%q", stderr)
	}
}

func TestDeployHelp(t *testing.T) {
	code, stdout, stderr := runWithOptions([]string{"deploy", "--help"}, Options{})
	if code != 0 {
		t.Fatalf("expected help success, got code=%d stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, "--dry-run") {
		t.Fatalf("expected --dry-run in help, got %q", stdout)
	}
	if !strings.Contains(stdout, "--force") {
		t.Fatalf("expected --force in help, got %q", stdout)
	}
	if !strings.Contains(stdout, "--socket") {
		t.Fatalf("expected --socket in help, got %q", stdout)
	}
	if !strings.Contains(stdout, "--cloud-url") {
		t.Fatalf("expected --cloud-url in help, got %q", stdout)
	}
}

func TestDeployRegistersWithCloud(t *testing.T) {
	dir := t.TempDir()
	getHealth := healthyStatus("edge-cloud", "aabbccdd")

	var gotReq cloud.RegisterDeviceRequest
	registerDevice := func(_ context.Context, baseURL string, req cloud.RegisterDeviceRequest) (cloud.RegisterDeviceResponse, error) {
		if baseURL != "https://cloud.example.com" {
			t.Fatalf("baseURL = %q, want https://cloud.example.com", baseURL)
		}
		gotReq = req
		return cloud.RegisterDeviceResponse{OK: true, DeviceID: req.DeviceID}, nil
	}

	code, stdout, stderr := runWithOptions(
		[]string{"deploy", "--key-dir", dir, "--cloud-url", "https://cloud.example.com"},
		Options{GetHealth: getHealth, RegisterDevice: registerDevice},
	)
	if code != 0 {
		t.Fatalf("expected success, got code=%d stderr=%q", code, stderr)
	}

	if gotReq.DeviceID != "edge-cloud" {
		t.Fatalf("DeviceID = %q, want edge-cloud", gotReq.DeviceID)
	}
	if len(gotReq.IdentityPubKeyHex) != 64 {
		t.Fatalf("IdentityPubKeyHex length = %d, want 64", len(gotReq.IdentityPubKeyHex))
	}
	if gotReq.EvidencePubKeyHex != "aabbccdd" {
		t.Fatalf("EvidencePubKeyHex = %q, want aabbccdd", gotReq.EvidencePubKeyHex)
	}
	if gotReq.RegisteredAtMs == 0 {
		t.Fatal("expected non-zero RegisteredAtMs")
	}
	if !strings.Contains(stdout, "successful") {
		t.Fatalf("expected successful registration message, got %q", stdout)
	}
}

func TestDeployCloudPayloadNeverContainsPrivateKey(t *testing.T) {
	dir := t.TempDir()
	getHealth := healthyStatus("edge-cloud", "")

	registerDevice := func(_ context.Context, _ string, req cloud.RegisterDeviceRequest) (cloud.RegisterDeviceResponse, error) {
		body, _ := json.Marshal(req)
		bodyStr := string(body)
		for _, forbidden := range []string{"private", "BEGIN PRIVATE KEY", "secret"} {
			if strings.Contains(bodyStr, forbidden) {
				t.Fatalf("cloud payload contains forbidden fragment %q: %s", forbidden, bodyStr)
			}
		}
		return cloud.RegisterDeviceResponse{OK: true}, nil
	}

	code, _, stderr := runWithOptions(
		[]string{"deploy", "--key-dir", dir, "--cloud-url", "https://cloud.example.com"},
		Options{GetHealth: getHealth, RegisterDevice: registerDevice},
	)
	if code != 0 {
		t.Fatalf("expected success, got code=%d stderr=%q", code, stderr)
	}
}

func TestDeployCloudErrorReported(t *testing.T) {
	dir := t.TempDir()
	getHealth := healthyStatus("edge-cloud", "")

	registerDevice := func(_ context.Context, _ string, _ cloud.RegisterDeviceRequest) (cloud.RegisterDeviceResponse, error) {
		return cloud.RegisterDeviceResponse{}, errors.New("cloud is down")
	}

	code, _, stderr := runWithOptions(
		[]string{"deploy", "--key-dir", dir, "--cloud-url", "https://cloud.example.com"},
		Options{GetHealth: getHealth, RegisterDevice: registerDevice},
	)
	if code == 0 {
		t.Fatal("expected failure when cloud registration fails")
	}
	if !strings.Contains(stderr, "cloud registration failed") {
		t.Fatalf("expected cloud registration error, got stderr=%q", stderr)
	}
}

func TestDeployCloudURLEnvVar(t *testing.T) {
	dir := t.TempDir()
	getHealth := healthyStatus("edge-env", "")
	t.Setenv("ORI_CLOUD_URL", "https://cloud-env.example.com")

	var gotBaseURL string
	registerDevice := func(_ context.Context, baseURL string, _ cloud.RegisterDeviceRequest) (cloud.RegisterDeviceResponse, error) {
		gotBaseURL = baseURL
		return cloud.RegisterDeviceResponse{OK: true}, nil
	}

	code, _, stderr := runWithOptions(
		[]string{"deploy", "--key-dir", dir},
		Options{GetHealth: getHealth, RegisterDevice: registerDevice},
	)
	if code != 0 {
		t.Fatalf("expected success, got code=%d stderr=%q", code, stderr)
	}
	if gotBaseURL != "https://cloud-env.example.com" {
		t.Fatalf("baseURL = %q, want https://cloud-env.example.com", gotBaseURL)
	}
}

func TestDeployNoCloudURLSkipsRegistration(t *testing.T) {
	dir := t.TempDir()
	getHealth := healthyStatus("edge-local", "")

	called := false
	registerDevice := func(_ context.Context, _ string, _ cloud.RegisterDeviceRequest) (cloud.RegisterDeviceResponse, error) {
		called = true
		return cloud.RegisterDeviceResponse{OK: true}, nil
	}

	code, stdout, _ := runWithOptions(
		[]string{"deploy", "--key-dir", dir},
		Options{GetHealth: getHealth, RegisterDevice: registerDevice},
	)
	if code != 0 {
		t.Fatalf("expected success, got code=%d", code)
	}
	if called {
		t.Fatal("cloud registration should not be called without cloud URL")
	}
	if !strings.Contains(stdout, "not configured") {
		t.Fatalf("expected not configured message, got %q", stdout)
	}
}
