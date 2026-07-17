// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package token

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// DefaultClockSkew is the maximum allowed clock skew when checking offline
// token timestamps. It matches the runtime default in ori-specs/offline-tokens/v1.md.
const DefaultClockSkew = 300 * time.Second

// RequiredTokenClaims are the fields that must be present in every offline
// token before it is presented to the runtime.
var RequiredTokenClaims = []string{"token_id", "device_id", "action_scope", "issued_at", "expires_at", "nonce", "signature"}

type OfflineUseResult struct {
	OK               bool   `json:"ok"`
	TokenFingerprint string `json:"token_fingerprint"`
}

// UseOptions configures the local offline-token validation performed by
// `ori token use` before the token is presented to the runtime.
type UseOptions struct {
	// TokenKeyPath is the filesystem path to the base64-encoded Ed25519
	// public key of the offline-token trust anchor. This is the key that
	// signs tokens, not the device identity key.
	TokenKeyPath string

	// ExpectedDeviceID must match the token's device_id claim.
	ExpectedDeviceID string

	// ClockSkew defaults to DefaultClockSkew when zero.
	ClockSkew time.Duration

	// Now defaults to time.Now when nil. Exposed for tests.
	Now func() time.Time
}

// UseOffline validates an offline Tier C token locally against the offline
// token trust-anchor public key without making network calls (CLI-1). It
// returns a fingerprint of the token so the raw value is never echoed or logged.
func UseOffline(raw string, opts UseOptions) (OfflineUseResult, error) {
	if raw == "" {
		return OfflineUseResult{}, fmt.Errorf("token must not be empty")
	}

	// Compute the fingerprint immediately and never include the raw token in
	// any return value or error message.
	sum := sha256.Sum256([]byte(raw))
	fingerprint := hex.EncodeToString(sum[:])[:16]

	payload, err := decodeTokenPayload(raw)
	if err != nil {
		return OfflineUseResult{}, fmt.Errorf("invalid token encoding: %w", err)
	}

	if err := validateRequiredClaims(payload); err != nil {
		return OfflineUseResult{}, err
	}

	if opts.TokenKeyPath == "" {
		return OfflineUseResult{}, fmt.Errorf("token key path is required")
	}
	if opts.ExpectedDeviceID == "" {
		return OfflineUseResult{}, fmt.Errorf("device-id is required")
	}

	publicKey, err := loadPublicKey(opts.TokenKeyPath)
	if err != nil {
		return OfflineUseResult{}, fmt.Errorf("load token key: %w", err)
	}

	if err := verifyTokenSignature(payload, publicKey); err != nil {
		return OfflineUseResult{}, fmt.Errorf("token signature verification failed: %w", err)
	}

	deviceID, _ := payload["device_id"].(string)
	if deviceID != opts.ExpectedDeviceID {
		return OfflineUseResult{}, fmt.Errorf("token device_id mismatch")
	}

	if err := checkTokenTimestamps(payload, opts.now()(), opts.clockSkew()); err != nil {
		return OfflineUseResult{}, err
	}

	return OfflineUseResult{OK: true, TokenFingerprint: fingerprint}, nil
}

func (o UseOptions) now() func() time.Time {
	if o.Now != nil {
		return o.Now
	}
	return time.Now
}

func (o UseOptions) clockSkew() time.Duration {
	if o.ClockSkew > 0 {
		return o.ClockSkew
	}
	return DefaultClockSkew
}

func decodeTokenPayload(raw string) (map[string]any, error) {
	txt := strings.TrimSpace(raw)
	if txt == "" {
		return nil, fmt.Errorf("empty token")
	}

	// Prefer base64url compact tokens; fallback to direct JSON.
	payloadTxt := txt
	if decoded, err := base64.RawURLEncoding.DecodeString(txt); err == nil {
		payloadTxt = string(decoded)
	} else if decoded, err := base64.URLEncoding.DecodeString(txt); err == nil {
		payloadTxt = string(decoded)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(payloadTxt), &payload); err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	if payload == nil {
		return nil, fmt.Errorf("payload is not a JSON object")
	}
	return payload, nil
}

func validateRequiredClaims(payload map[string]any) error {
	for _, claim := range RequiredTokenClaims {
		if payload[claim] == nil {
			return fmt.Errorf("missing required claim: %s", claim)
		}
	}
	// String claims must be non-empty after trimming.
	for _, claim := range []string{"token_id", "action_scope", "nonce"} {
		value, ok := payload[claim].(string)
		if !ok {
			return fmt.Errorf("required claim %s must be a string", claim)
		}
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("required claim %s must not be empty", claim)
		}
	}
	return nil
}

func loadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}
	encoded := strings.TrimSpace(string(data))
	if encoded == "" {
		return nil, fmt.Errorf("public key file is empty")
	}
	pub, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key length: %d", len(pub))
	}
	return ed25519.PublicKey(pub), nil
}

func canonicalTokenPayload(payload map[string]any) ([]byte, error) {
	canonical := make(map[string]any, len(payload))
	for k, v := range payload {
		if k == "signature" {
			continue
		}
		canonical[k] = v
	}

	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(canonical); err != nil {
		return nil, err
	}
	// json.Encoder appends a trailing newline; Python's json.dumps does not.
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func verifyTokenSignature(payload map[string]any, publicKey ed25519.PublicKey) error {
	signatureField, ok := payload["signature"].(string)
	if !ok || strings.TrimSpace(signatureField) == "" {
		return fmt.Errorf("missing signature field")
	}

	scheme, signatureB64, found := strings.Cut(signatureField, ":")
	if !found {
		return fmt.Errorf("invalid signature format")
	}
	if strings.ToLower(scheme) != "ed25519" {
		return fmt.Errorf("unsupported signature scheme: %q", scheme)
	}

	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	message, err := canonicalTokenPayload(payload)
	if err != nil {
		return fmt.Errorf("canonicalize payload: %w", err)
	}

	if !ed25519.Verify(publicKey, message, signature) {
		return fmt.Errorf("signature does not verify")
	}
	return nil
}

func checkTokenTimestamps(payload map[string]any, now time.Time, skew time.Duration) error {
	issuedAt, err := jsonNumberToInt64(payload["issued_at"])
	if err != nil {
		return fmt.Errorf("invalid issued_at: %w", err)
	}
	expiresAt, err := jsonNumberToInt64(payload["expires_at"])
	if err != nil {
		return fmt.Errorf("invalid expires_at: %w", err)
	}

	nowSec := now.Unix()
	if issuedAt > nowSec+int64(skew.Seconds()) {
		return fmt.Errorf("token issued in the future")
	}
	if expiresAt < nowSec-int64(skew.Seconds()) {
		return fmt.Errorf("token expired")
	}
	return nil
}

func jsonNumberToInt64(v any) (int64, error) {
	switch n := v.(type) {
	case float64:
		return int64(n), nil
	case int:
		return int64(n), nil
	case int64:
		return n, nil
	case json.Number:
		return n.Int64()
	default:
		return 0, fmt.Errorf("not a number: %T", v)
	}
}
