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

		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	client := New(server.URL)
	err := client.RegisterKeypair(context.Background(), "api-key-123", "edge-1", RegisterKeypairRequest{
		IdentityPubKeyHex: "00112233",
	})
	if err != nil {
		t.Fatalf("RegisterKeypair failed: %v", err)
	}
	if got.IdentityPubKeyHex != "00112233" {
		t.Fatalf("identity_pubkey_hex = %q, want %q", got.IdentityPubKeyHex, "00112233")
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
	err := client.RegisterKeypair(context.Background(), "api-key", "edge-1", RegisterKeypairRequest{
		IdentityPubKeyHex: "00112233",
	})
	if err != nil {
		t.Fatalf("RegisterKeypair failed: %v", err)
	}
}

func TestRegisterKeypairRequiresDeviceAPIKey(t *testing.T) {
	client := New("https://cloud.example.com")
	err := client.RegisterKeypair(context.Background(), "", "edge-1", RegisterKeypairRequest{})
	if err == nil {
		t.Fatal("expected error without device API key")
	}
}

func TestRegisterKeypairRequiresDeviceID(t *testing.T) {
	client := New("https://cloud.example.com")
	err := client.RegisterKeypair(context.Background(), "api-key", "", RegisterKeypairRequest{})
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
	err := client.RegisterKeypair(context.Background(), "api-key", "edge-1", RegisterKeypairRequest{})
	if err == nil {
		t.Fatal("expected error for non-2xx response")
	}
	if !strings.Contains(err.Error(), "409") {
		t.Fatalf("expected 409 in error, got %v", err)
	}
}

func TestRegisterKeypairReturnsErrorOnInvalidBaseURL(t *testing.T) {
	client := New("://invalid-url")
	err := client.RegisterKeypair(context.Background(), "api-key", "edge-1", RegisterKeypairRequest{})
	if err == nil {
		t.Fatal("expected error for invalid base URL")
	}
}
