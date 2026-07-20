// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package cloud

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRegisterDevicePostsExpectedPayload(t *testing.T) {
	var got RegisterDeviceRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if r.URL.Path != registerDevicePath {
			t.Errorf("path = %q, want %q", r.URL.Path, registerDevicePath)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("content-type = %q, want application/json", ct)
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("decode body: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"ok":true,"device_id":"edge-1"}`))
	}))
	defer server.Close()

	client := New(server.URL)
	req := RegisterDeviceRequest{
		DeviceID:          "edge-1",
		IdentityPubKeyHex: "00112233",
		EvidencePubKeyHex: "aabbccdd",
		RegisteredAtMs:    1234,
	}
	resp, err := client.RegisterDevice(context.Background(), req)
	if err != nil {
		t.Fatalf("RegisterDevice failed: %v", err)
	}
	if !resp.OK {
		t.Fatal("expected OK response")
	}

	if got.DeviceID != req.DeviceID {
		t.Fatalf("device_id = %q, want %q", got.DeviceID, req.DeviceID)
	}
	if got.IdentityPubKeyHex != req.IdentityPubKeyHex {
		t.Fatalf("identity_pubkey_hex = %q, want %q", got.IdentityPubKeyHex, req.IdentityPubKeyHex)
	}
	if got.EvidencePubKeyHex != req.EvidencePubKeyHex {
		t.Fatalf("evidence_pubkey_hex = %q, want %q", got.EvidencePubKeyHex, req.EvidencePubKeyHex)
	}
	if got.RegisteredAtMs != req.RegisteredAtMs {
		t.Fatalf("registered_at_ms = %d, want %d", got.RegisteredAtMs, req.RegisteredAtMs)
	}
}

func TestRegisterDeviceNeverContainsPrivateKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		bodyStr := string(body)
		for _, forbidden := range []string{"private", "BEGIN PRIVATE KEY", "secret"} {
			if strings.Contains(bodyStr, forbidden) {
				t.Fatalf("request body contains forbidden fragment %q: %s", forbidden, bodyStr)
			}
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	client := New(server.URL)
	_, err := client.RegisterDevice(context.Background(), RegisterDeviceRequest{
		DeviceID:          "edge-1",
		IdentityPubKeyHex: "00112233",
	})
	if err != nil {
		t.Fatalf("RegisterDevice failed: %v", err)
	}
}

func TestRegisterDeviceReturnsErrorOnNon2xx(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"device already registered"}`))
	}))
	defer server.Close()

	client := New(server.URL)
	_, err := client.RegisterDevice(context.Background(), RegisterDeviceRequest{DeviceID: "edge-1"})
	if err == nil {
		t.Fatal("expected error for non-2xx response")
	}
	if !strings.Contains(err.Error(), "409") {
		t.Fatalf("expected 409 in error, got %v", err)
	}
}

func TestRegisterDeviceReturnsErrorOnInvalidBaseURL(t *testing.T) {
	client := New("://invalid-url")
	_, err := client.RegisterDevice(context.Background(), RegisterDeviceRequest{})
	if err == nil {
		t.Fatal("expected error for invalid base URL")
	}
}
