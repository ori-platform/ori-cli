// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package token

import "testing"

func TestUseOfflineRejectsEmptyToken(t *testing.T) {
	if _, err := UseOffline(""); err == nil {
		t.Fatal("expected empty token error")
	}
}

func TestUseOfflineDoesNotEchoSecretToken(t *testing.T) {
	result, err := UseOffline("secret-token")
	if err != nil {
		t.Fatalf("UseOffline returned error: %v", err)
	}
	if !result.OK {
		t.Fatal("expected ok result")
	}
	if result.TokenFingerprint == "" {
		t.Fatal("expected token fingerprint")
	}
	if result.TokenFingerprint == "secret-token" {
		t.Fatal("token secret was echoed")
	}
}
