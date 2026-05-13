// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"bytes"
	"strings"
	"testing"
)

func TestErrorJSON(t *testing.T) {
	var b bytes.Buffer
	Error(&b, true, "boom")
	if !strings.Contains(b.String(), `"error": "boom"`) {
		t.Fatalf("unexpected JSON error: %s", b.String())
	}
}
