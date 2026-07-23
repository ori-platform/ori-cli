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

func TestRegisterKeypairPostsExpectedPayload(t *testing.T) {
	var got RegisterKeypairRequest
	var authHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if want := "/devices/edge-1/keypair"; r.URL.Path != want {
			t.Errorf("path = %q, want %q", r.URL.Path, want)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("content-type = %q, want application/json", ct)
		}
		authHeader = r.Header.Get("Authorization")

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
	req := RegisterKeypairRequest{
		DeviceID:          "edge-1",
		IdentityPubKeyHex: "00112233",
		RegisteredAtMs:    1234,
	}
	resp, err := client.RegisterKeypair(context.Background(), "api-key-123", req)
	if err != nil {
		t.Fatalf("RegisterKeypair failed: %v", err)
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
	if got.RegisteredAtMs != req.RegisteredAtMs {
		t.Fatalf("registered_at_ms = %d, want %d", got.RegisteredAtMs, req.RegisteredAtMs)
	}
	if authHeader != "Bearer api-key-123" {
		t.Fatalf("authorization header = %q, want Bearer api-key-123", authHeader)
	}
}

func TestRegisterKeypairNeverContainsPrivateKey(t *testing.T) {
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
	_, err := client.RegisterKeypair(context.Background(), "api-key", RegisterKeypairRequest{
		DeviceID:          "edge-1",
		IdentityPubKeyHex: "00112233",
	})
	if err != nil {
		t.Fatalf("RegisterKeypair failed: %v", err)
	}
}

func TestRegisterKeypairRequiresDeviceAPIKey(t *testing.T) {
	client := New("https://cloud.example.com")
	_, err := client.RegisterKeypair(context.Background(), "", RegisterKeypairRequest{DeviceID: "edge-1"})
	if err == nil {
		t.Fatal("expected error without device API key")
	}
}

func TestRegisterKeypairRequiresDeviceID(t *testing.T) {
	client := New("https://cloud.example.com")
	_, err := client.RegisterKeypair(context.Background(), "api-key", RegisterKeypairRequest{})
	if err == nil {
		t.Fatal("expected error without device ID")
	}
}

func TestRegisterKeypairReturnsErrorOnNon2xx(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"keypair already registered"}`))
	}))
	defer server.Close()

	client := New(server.URL)
	_, err := client.RegisterKeypair(context.Background(), "api-key", RegisterKeypairRequest{DeviceID: "edge-1"})
	if err == nil {
		t.Fatal("expected error for non-2xx response")
	}
	if !strings.Contains(err.Error(), "409") {
		t.Fatalf("expected 409 in error, got %v", err)
	}
}

func TestRegisterKeypairReturnsErrorOnInvalidBaseURL(t *testing.T) {
	client := New("://invalid-url")
	_, err := client.RegisterKeypair(context.Background(), "api-key", RegisterKeypairRequest{DeviceID: "edge-1"})
	if err == nil {
		t.Fatal("expected error for invalid base URL")
	}
}
