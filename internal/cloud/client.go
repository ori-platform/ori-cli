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
	"time"
)

// RegisterKeypairRequest is the CLI-side payload for registering a device's
// Ed25519 identity public key with ori-cloud. It contains only public key
// material; private keys must never be included.
type RegisterKeypairRequest struct {
	DeviceID          string `json:"device_id"`
	IdentityPubKeyHex string `json:"identity_pubkey_hex"`
	RegisteredAtMs    int64  `json:"registered_at_ms"`
}

// RegisterKeypairResponse is the minimal successful response shape from the
// cloud keypair registration endpoint. Callers should treat non-2xx status
// codes as errors rather than inspecting this response alone.
type RegisterKeypairResponse struct {
	OK       bool   `json:"ok"`
	DeviceID string `json:"device_id,omitempty"`
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
// body never contains private key material.
func (c Client) RegisterKeypair(ctx context.Context, deviceAPIKey string, req RegisterKeypairRequest) (RegisterKeypairResponse, error) {
	if deviceAPIKey == "" {
		return RegisterKeypairResponse{}, fmt.Errorf("device API key is required for keypair registration")
	}
	if req.DeviceID == "" {
		return RegisterKeypairResponse{}, fmt.Errorf("device ID is required for keypair registration")
	}

	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return RegisterKeypairResponse{}, fmt.Errorf("invalid cloud base URL: %w", err)
	}
	u = u.JoinPath("devices", req.DeviceID, "keypair")

	body, err := json.Marshal(req)
	if err != nil {
		return RegisterKeypairResponse{}, fmt.Errorf("encode keypair payload: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return RegisterKeypairResponse{}, fmt.Errorf("create keypair request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+deviceAPIKey)

	httpResp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return RegisterKeypairResponse{}, fmt.Errorf("keypair registration request failed: %w", err)
	}
	defer httpResp.Body.Close()

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return RegisterKeypairResponse{}, fmt.Errorf("read keypair registration response: %w", err)
	}

	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		return RegisterKeypairResponse{}, fmt.Errorf("keypair registration returned %s: %s", httpResp.Status, string(respBody))
	}

	var resp RegisterKeypairResponse
	if len(respBody) > 0 {
		if err := json.Unmarshal(respBody, &resp); err != nil {
			return RegisterKeypairResponse{}, fmt.Errorf("decode keypair registration response: %w", err)
		}
	}
	resp.OK = true
	return resp, nil
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

// Now returns the current Unix timestamp in milliseconds.
func Now() int64 {
	return time.Now().UnixMilli()
}
