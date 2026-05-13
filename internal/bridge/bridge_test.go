// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package bridge

import (
	"context"
	"testing"
	"time"
)

func TestDefaultRunner(t *testing.T) {
	r := DefaultRunner()
	if r.Python != "python3" || r.Module != "ori.cli_bridge" {
		t.Fatalf("unexpected default runner: %#v", r)
	}
}

func TestRunnerReportsFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := Runner{Python: "definitely-missing-python"}.Run(ctx, "config-validate")
	if err == nil {
		t.Fatal("expected bridge failure")
	}
}
