// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package token

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

type OfflineUseResult struct {
	OK               bool   `json:"ok"`
	TokenFingerprint string `json:"token_fingerprint"`
}

func UseOffline(raw string) (OfflineUseResult, error) {
	// TODO: validate against the on-device Ed25519 keypair at ~/.ori/device.pub,
	// then present the token to the local runtime without contacting ori-cloud.
	if raw == "" {
		return OfflineUseResult{}, fmt.Errorf("token must not be empty")
	}
	sum := sha256.Sum256([]byte(raw))
	return OfflineUseResult{OK: true, TokenFingerprint: hex.EncodeToString(sum[:])[:16]}, nil
}
