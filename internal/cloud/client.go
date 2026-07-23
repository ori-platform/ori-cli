// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package cloud

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// RegisterKeypairRequest is the CLI-side payload for registering a device's
// Ed25519 identity public key with ori-cloud. It contains only public key
// material; private keys must never be included.
//
// TODO(cloud-contract): The exact request/response DTO for
// POST /devices/:id/keypair is not yet implemented in ori-cloud. This shape is
// intentionally minimal (device identity only) and must be updated once the
// cloud contract is pinned. Registration time is receiver-assigned and is not
// sent by the CLI.
type RegisterKeypairRequest struct {
	IdentityPubKeyHex string `json:"identity_pubkey_hex"`
}

type Client struct {
	BaseURL string
	HTTP    *http.Client
}

func New(baseURL string) Client {
	return Client{BaseURL: baseURL, HTTP: http.DefaultClient}
}

// RegisterKeypair POSTs the device identity public key to
// POST /devices/:id/keypair authenticated by the device API key. The request
// body never contains private key material. A 2xx response is treated as
// success; any non-2xx response is returned as an error.
func (c Client) RegisterKeypair(ctx context.Context, deviceAPIKey, deviceID string, req RegisterKeypairRequest) error {
	if deviceAPIKey == "" {
		return fmt.Errorf("device API key is required for keypair registration")
	}
	if deviceID == "" {
		return fmt.Errorf("device ID is required for keypair registration")
	}

	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return fmt.Errorf("invalid cloud base URL: %w", err)
	}
	u = u.JoinPath("devices", deviceID, "keypair")

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("encode keypair payload: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create keypair request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+deviceAPIKey)

	httpResp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return fmt.Errorf("keypair registration request failed: %w", err)
	}
	defer httpResp.Body.Close()

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return fmt.Errorf("read keypair registration response: %w", err)
	}

	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		return fmt.Errorf("keypair registration returned %s: %s", httpResp.Status, string(respBody))
	}

	return nil
}

// PublicKeyHex returns the 64-character lowercase hex encoding of an Ed25519
// public key.
func PublicKeyHex(pub ed25519.PublicKey) string {
	return fmt.Sprintf("%064x", pub)
}

// EncodeDeviceAPIKey returns the standard base64 encoding of the device API
// key bytes. The exact wire format is defined by ori-cloud; this helper keeps
// encoding consistent across the CLI.
func EncodeDeviceAPIKey(key []byte) string {
	return base64.StdEncoding.EncodeToString(key)
}
