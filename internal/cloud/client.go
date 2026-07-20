// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package cloud

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const registerDevicePath = "/v1/devices"

// RegisterDeviceRequest is the CLI-side payload for registering a newly
// provisioned device identity and its optional Verity evidence anchor.
// It contains only public key material; private keys must never be included.
type RegisterDeviceRequest struct {
	DeviceID          string `json:"device_id"`
	IdentityPubKeyHex string `json:"identity_pubkey_hex"`
	EvidencePubKeyHex string `json:"evidence_pubkey_hex,omitempty"`
	RegisteredAtMs    int64  `json:"registered_at_ms"`
}

// RegisterDeviceResponse is the minimal successful response shape from the
// cloud registration endpoint. Callers should treat non-2xx status codes as
// errors rather than inspecting this response alone.
type RegisterDeviceResponse struct {
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

// RegisterDevice POSTs the public device identity and evidence anchor to the
// cloud device registry. The request body never contains private key material.
func (c Client) RegisterDevice(ctx context.Context, req RegisterDeviceRequest) (RegisterDeviceResponse, error) {
	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return RegisterDeviceResponse{}, fmt.Errorf("invalid cloud base URL: %w", err)
	}
	u = u.JoinPath(registerDevicePath)

	body, err := json.Marshal(req)
	if err != nil {
		return RegisterDeviceResponse{}, fmt.Errorf("encode registration payload: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return RegisterDeviceResponse{}, fmt.Errorf("create registration request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return RegisterDeviceResponse{}, fmt.Errorf("cloud registration request failed: %w", err)
	}
	defer httpResp.Body.Close()

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return RegisterDeviceResponse{}, fmt.Errorf("read cloud registration response: %w", err)
	}

	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		return RegisterDeviceResponse{}, fmt.Errorf("cloud registration returned %s: %s", httpResp.Status, string(respBody))
	}

	var resp RegisterDeviceResponse
	if len(respBody) > 0 {
		if err := json.Unmarshal(respBody, &resp); err != nil {
			return RegisterDeviceResponse{}, fmt.Errorf("decode cloud registration response: %w", err)
		}
	}
	resp.OK = true
	return resp, nil
}

// Now returns the current Unix timestamp in milliseconds.
func Now() int64 {
	return time.Now().UnixMilli()
}
