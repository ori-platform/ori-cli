// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package cloud

import "net/http"

type Client struct {
	BaseURL string
	HTTP    *http.Client
}

func New(baseURL string) Client {
	return Client{BaseURL: baseURL, HTTP: http.DefaultClient}
}
