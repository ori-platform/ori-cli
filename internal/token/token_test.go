// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package token

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writePublicKey(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "device.pub")
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(pub)), 0o600); err != nil {
		t.Fatalf("write public key: %v", err)
	}
	return path
}

func generateKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

func mintToken(t *testing.T, priv ed25519.PrivateKey, overrides map[string]any) string {
	t.Helper()
	now := time.Now().Unix()
	payload := map[string]any{
		"token_id":     "tok-01",
		"device_id":    "dev-01",
		"action_scope": "open_safety_circuit",
		"issued_at":    now - 5,
		"expires_at":   now + 120,
		"nonce":        "n1",
	}
	for k, v := range overrides {
		payload[k] = v
	}

	canonical, err := canonicalTokenPayload(payload)
	if err != nil {
		t.Fatalf("canonicalize payload: %v", err)
	}
	signature := ed25519.Sign(priv, canonical)
	payload["signature"] = "ed25519:" + base64.StdEncoding.EncodeToString(signature)

	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func TestUseOfflineRejectsEmptyToken(t *testing.T) {
	pub, _ := generateKeyPair(t)
	_, err := UseOffline("", UseOptions{DeviceKeyPath: writePublicKey(t, pub)})
	if err == nil {
		t.Fatal("expected empty token error")
	}
}

func TestUseOfflineRequiresDeviceKey(t *testing.T) {
	_, priv := generateKeyPair(t)
	token := mintToken(t, priv, nil)
	_, err := UseOffline(token, UseOptions{})
	if err == nil || !strings.Contains(err.Error(), "device key path is required") {
		t.Fatalf("expected device key required error, got: %v", err)
	}
}

func TestUseOfflineAcceptsValidToken(t *testing.T) {
	pub, priv := generateKeyPair(t)
	tok := mintToken(t, priv, nil)
	result, err := UseOffline(tok, UseOptions{
		DeviceKeyPath: writePublicKey(t, pub),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.OK {
		t.Fatal("expected ok result")
	}
	if result.TokenFingerprint == "" {
		t.Fatal("expected token fingerprint")
	}
	if strings.Contains(result.TokenFingerprint, tok) {
		t.Fatal("raw token leaked into fingerprint")
	}
}

func TestUseOfflineDoesNotEchoSecretToken(t *testing.T) {
	pub, priv := generateKeyPair(t)
	tok := mintToken(t, priv, nil)
	_, err := UseOffline(tok, UseOptions{DeviceKeyPath: writePublicKey(t, pub)})
	if err != nil {
		t.Fatalf("UseOffline returned error: %v", err)
	}
	// Error paths must never include the raw token. Empty key path is a safe
	// control error that does not touch the token body.
	_, err = UseOffline(tok, UseOptions{})
	if err != nil && strings.Contains(err.Error(), tok) {
		t.Fatal("raw token leaked into error message")
	}
}

func TestUseOfflineRejectsInvalidSignature(t *testing.T) {
	pub, _ := generateKeyPair(t)
	_, wrongPriv := generateKeyPair(t)
	tok := mintToken(t, wrongPriv, nil)
	_, err := UseOffline(tok, UseOptions{DeviceKeyPath: writePublicKey(t, pub)})
	if err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("expected signature error, got: %v", err)
	}
}

func TestUseOfflineRejectsTamperedToken(t *testing.T) {
	pub, priv := generateKeyPair(t)
	tok := mintToken(t, priv, nil)

	// Decode, tamper with device_id, re-encode without resigning.
	decoded, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		t.Fatalf("decode token: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(decoded, &payload); err != nil {
		t.Fatalf("unmarshal token: %v", err)
	}
	payload["device_id"] = "dev-attacker"
	tamperedRaw, _ := json.Marshal(payload)
	tamperedTok := base64.RawURLEncoding.EncodeToString(tamperedRaw)

	_, err = UseOffline(tamperedTok, UseOptions{
		DeviceKeyPath: writePublicKey(t, pub),
	})
	if err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("expected signature error after tampering, got: %v", err)
	}
}

func TestUseOfflineRejectsDeviceIDMismatch(t *testing.T) {
	pub, priv := generateKeyPair(t)
	tok := mintToken(t, priv, nil)
	_, err := UseOffline(tok, UseOptions{
		DeviceKeyPath:    writePublicKey(t, pub),
		ExpectedDeviceID: "dev-other",
	})
	if err == nil || !strings.Contains(err.Error(), "device_id mismatch") {
		t.Fatalf("expected device_id mismatch error, got: %v", err)
	}
}

func TestUseOfflineRejectsExpiredToken(t *testing.T) {
	pub, priv := generateKeyPair(t)
	now := time.Now().Unix()
	tok := mintToken(t, priv, map[string]any{
		"issued_at":  now - 600,
		"expires_at": now - 400,
	})
	_, err := UseOffline(tok, UseOptions{
		DeviceKeyPath: writePublicKey(t, pub),
		Now:           func() time.Time { return time.Now() },
	})
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expired error, got: %v", err)
	}
}

func TestUseOfflineRejectsFutureIssuedAt(t *testing.T) {
	pub, priv := generateKeyPair(t)
	now := time.Now().Unix()
	tok := mintToken(t, priv, map[string]any{
		"issued_at":  now + 1000,
		"expires_at": now + 2000,
	})
	_, err := UseOffline(tok, UseOptions{DeviceKeyPath: writePublicKey(t, pub)})
	if err == nil || !strings.Contains(err.Error(), "future") {
		t.Fatalf("expected future issued_at error, got: %v", err)
	}
}

func TestUseOfflineRejectsMissingSignature(t *testing.T) {
	pub, _ := generateKeyPair(t)
	payload := map[string]any{
		"token_id": "tok-01", "device_id": "dev-01",
		"action_scope": "*", "issued_at": 1, "expires_at": 2, "nonce": "n1",
	}
	raw, _ := json.Marshal(payload)
	tok := base64.RawURLEncoding.EncodeToString(raw)
	_, err := UseOffline(tok, UseOptions{DeviceKeyPath: writePublicKey(t, pub)})
	if err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("expected missing signature error, got: %v", err)
	}
}

func TestUseOfflineRejectsMalformedToken(t *testing.T) {
	pub, _ := generateKeyPair(t)
	_, err := UseOffline("not-base64-or-json", UseOptions{DeviceKeyPath: writePublicKey(t, pub)})
	if err == nil {
		t.Fatal("expected malformed token error")
	}
}

func TestUseOfflineIsOfflineNoNetwork(t *testing.T) {
	pub, priv := generateKeyPair(t)
	tok := mintToken(t, priv, nil)
	start := time.Now()
	_, err := UseOffline(tok, UseOptions{DeviceKeyPath: writePublicKey(t, pub)})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Pure crypto/file IO should complete in well under a second; no network.
	if elapsed > time.Second {
		t.Fatalf("token validation took too long, possible network call: %v", elapsed)
	}
}

func TestCanonicalTokenPayloadExcludesSignature(t *testing.T) {
	payload := map[string]any{
		"token_id": "t1", "signature": "should-be-ignored",
	}
	canonical, err := canonicalTokenPayload(payload)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if strings.Contains(string(canonical), "signature") {
		t.Fatal("signature field was included in canonical payload")
	}
}
