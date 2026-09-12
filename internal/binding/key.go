// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package binding

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
)

// SigningKeyName is the form a binding names its key in.
func SigningKeyName(pub ed25519.PublicKey) string {
	return "ed25519:" + base64.StdEncoding.EncodeToString(pub)
}

// ParsePrivateKey reads an ed25519 private key in either spelling a
// commissioning key is kept in: PKCS#8 PEM, as this tool's own key store
// writes, or the 32-byte seed as 64 hex characters, as the contract's vectors
// carry it. No error names any of the bytes it was given.
func ParsePrivateKey(data []byte) (ed25519.PrivateKey, error) {
	trimmed := bytes.TrimSpace(data)
	if block, _ := pem.Decode(trimmed); block != nil {
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.New("the PEM block does not hold a PKCS#8 private key")
		}
		key, ok := parsed.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("the private key is not ed25519, got %T", parsed)
		}
		return key, nil
	}
	if len(trimmed) == 2*ed25519.SeedSize {
		seed, err := hex.DecodeString(string(trimmed))
		if err == nil {
			return ed25519.NewKeyFromSeed(seed), nil
		}
	}
	return nil, errors.New(
		"the key is neither a PKCS#8 PEM ed25519 private key nor a 64-character hex seed")
}
