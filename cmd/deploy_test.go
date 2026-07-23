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

	"github.com/ori-platform/ori-cli/internal/deploy"
	"github.com/ori-platform/ori-cli/internal/rpc"
)

func healthyStatus(deviceID string, evidencePub string) func(context.Context, string) (rpc.RuntimeHealthStatus, error) {
	return func(_ context.Context, _ string) (rpc.RuntimeHealthStatus, error) {
		es := rpc.EvidenceStatus{Enabled: false, Available: false, PublicKeyHex: ""}
		if evidencePub != "" {
			es = rpc.EvidenceStatus{Enabled: true, Available: true, PublicKeyHex: evidencePub}
		}
		return rpc.RuntimeHealthStatus{
			DeviceID:  deviceID,
			Evidence:  es,
			Canonical: true,
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
		t.Fatalf("expected generated message, got stdout=%q", stdout)
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

func TestDeployReusesExistingKeypairWithoutForce(t *testing.T) {
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

	code, stdout, stderr := runWithOptions([]string{"deploy", "--key-dir", dir}, Options{GetHealth: getHealth})
	if code != 0 {
		t.Fatalf("second deploy failed with code=%d stderr=%q", code, stderr)
	}

	secondPub, err := os.ReadFile(filepath.Join(dir, deploy.PublicKeyFile))
	if err != nil {
		t.Fatalf("read second public key: %v", err)
	}
	if string(firstPub) != string(secondPub) {
		t.Fatal("expected same public key on retry without --force")
	}
	if !strings.Contains(stdout, "already present") && !strings.Contains(stdout, "using existing keys") {
		t.Fatalf("expected already-present message, got %q", stdout)
	}
}

func TestDeployFailsWithoutDeviceID(t *testing.T) {
	dir := t.TempDir()
	getHealth := healthyStatus("", "")
	code, _, stderr := runWithOptions([]string{"deploy", "--key-dir", dir}, Options{GetHealth: getHealth})
	if code == 0 {
		t.Fatal("expected failure without device_id")
	}
	if !strings.Contains(stderr, "device_id") {
		t.Fatalf("expected device_id error, got stderr=%q", stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, deploy.PrivateKeyFile)); err == nil {
		t.Fatal("private key should not be written when health validation fails")
	}
}

func TestDeployRejectsLegacyHealthBeforeWritingKeys(t *testing.T) {
	dir := t.TempDir()
	legacy, err := rpc.ParseHealth([]byte(`{"status":"ok","device_id":"edge-legacy"}`))
	if err != nil {
		t.Fatalf("parse legacy health fixture: %v", err)
	}
	getHealth := func(_ context.Context, _ string) (rpc.RuntimeHealthStatus, error) {
		return legacy, nil
	}

	code, _, stderr := runWithOptions([]string{"deploy", "--key-dir", dir}, Options{GetHealth: getHealth})
	if code == 0 {
		t.Fatal("expected legacy health response to be refused")
	}
	if !strings.Contains(stderr, "canonical v1 envelope") {
		t.Fatalf("expected canonical-envelope error, got stderr=%q", stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, deploy.PrivateKeyFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("private key should not be written after legacy health: %v", err)
	}
}

func TestDeployFailsOnHealthErrorEnvelope(t *testing.T) {
	dir := t.TempDir()
	getHealth := func(_ context.Context, _ string) (rpc.RuntimeHealthStatus, error) {
		return rpc.ParseHealth([]byte(`{"schema_version":1,"ok":false,"error":{"code":"internal_error","detail":"snapshot failed"}}`))
	}
	code, _, stderr := runWithOptions([]string{"deploy", "--key-dir", dir}, Options{GetHealth: getHealth})
	if code == 0 {
		t.Fatal("expected failure for ok=false health envelope")
	}
	if !strings.Contains(stderr, "internal_error") {
		t.Fatalf("expected internal_error in stderr, got %q", stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, deploy.PrivateKeyFile)); err == nil {
		t.Fatal("private key should not be written when health envelope fails")
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
}

func TestDeployFailsWhenEvidenceEnabledButAnchorMissing(t *testing.T) {
	dir := t.TempDir()
	getHealth := func(_ context.Context, _ string) (rpc.RuntimeHealthStatus, error) {
		return rpc.RuntimeHealthStatus{
			DeviceID:  "edge-3",
			Evidence:  rpc.EvidenceStatus{Enabled: true, Available: false, PublicKeyHex: ""},
			Canonical: true,
		}, nil
	}
	code, _, stderr := runWithOptions([]string{"deploy", "--key-dir", dir}, Options{GetHealth: getHealth})
	if code == 0 {
		t.Fatal("expected failure when evidence enabled but anchor missing")
	}
	if !strings.Contains(stderr, "evidence layer is enabled") {
		t.Fatalf("expected evidence state unavailable error, got stderr=%q", stderr)
	}
}

func TestDeployFailsOnInconsistentDisabledEvidenceState(t *testing.T) {
	dir := t.TempDir()
	getHealth := func(_ context.Context, _ string) (rpc.RuntimeHealthStatus, error) {
		return rpc.RuntimeHealthStatus{
			DeviceID: "edge-3",
			Evidence: rpc.EvidenceStatus{
				Enabled:      false,
				Available:    true,
				PublicKeyHex: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
			},
			Canonical: true,
		}, nil
	}
	code, _, stderr := runWithOptions([]string{"deploy", "--key-dir", dir}, Options{GetHealth: getHealth})
	if code == 0 {
		t.Fatal("expected inconsistent disabled evidence state to fail")
	}
	if !strings.Contains(stderr, "disabled but runtime health reported active evidence material") {
		t.Fatalf("expected inconsistent evidence error, got stderr=%q", stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, deploy.PrivateKeyFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("private key should not be written after inconsistent evidence health: %v", err)
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
	getHealth := healthyStatus("edge-json", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
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
	if payload["cloud_registration"] != "deferred" {
		t.Fatalf("expected cloud_registration=deferred, got %v", payload["cloud_registration"])
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
	for _, flag := range []string{"--dry-run", "--force", "--socket"} {
		if !strings.Contains(stdout, flag) {
			t.Fatalf("expected %s in help, got %q", flag, stdout)
		}
	}
	for _, flag := range []string{"--cloud-url", "--device-api-key", "--yes"} {
		if strings.Contains(stdout, flag) {
			t.Fatalf("did not expect unpinned cloud mutation flag %s in help, got %q", flag, stdout)
		}
	}
	if !strings.Contains(stdout, "Cloud registration is deliberately deferred") {
		t.Fatalf("expected explicit cloud deferral in help, got %q", stdout)
	}
}

func TestDeployRejectsUnpinnedCloudMutationFlagsBeforeWritingKeys(t *testing.T) {
	dir := t.TempDir()
	code, _, stderr := runWithOptions(
		[]string{"deploy", "--key-dir", dir, "--cloud-url", "https://cloud.example.com"},
		Options{},
	)
	if code == 0 {
		t.Fatal("expected removed cloud mutation flag to fail")
	}
	if !strings.Contains(stderr, "unknown flag: --cloud-url") {
		t.Fatalf("expected unknown cloud flag error, got stderr=%q", stderr)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read key directory: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected no key files after rejected flag, got %d entries", len(entries))
	}
}

func TestDeployReportsCloudRegistrationDeferred(t *testing.T) {
	dir := t.TempDir()
	getHealth := healthyStatus("edge-local", "")

	code, stdout, stderr := runWithOptions(
		[]string{"deploy", "--key-dir", dir},
		Options{GetHealth: getHealth},
	)
	if code != 0 {
		t.Fatalf("expected success, got code=%d stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, "Cloud registration: deferred pending a pinned authenticated ori-cloud contract.") {
		t.Fatalf("expected explicit deferred registration message, got %q", stdout)
	}
}

func TestDeployFailsOnInvalidEvidenceAnchorFormat(t *testing.T) {
	dir := t.TempDir()
	getHealth := healthyStatus("edge-4", "aabbccdd")
	code, _, stderr := runWithOptions([]string{"deploy", "--key-dir", dir}, Options{GetHealth: getHealth})
	if code == 0 {
		t.Fatal("expected failure for invalid evidence anchor format")
	}
	if !strings.Contains(stderr, "64 lowercase hexadecimal") {
		t.Fatalf("expected hex anchor format error, got stderr=%q", stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, deploy.PrivateKeyFile)); err == nil {
		t.Fatal("private key should not be written when evidence anchor is invalid")
	}
}
