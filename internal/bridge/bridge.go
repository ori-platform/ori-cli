// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package bridge

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
)

type Runner struct {
	Python string
	Module string
}

type Result struct {
	Stdout []byte
	Stderr []byte
}

func DefaultRunner() Runner {
	return Runner{Python: "python3", Module: "ori.cli_bridge"}
}

func (r Runner) Run(ctx context.Context, args ...string) (Result, error) {
	python := r.Python
	if python == "" {
		python = "python3"
	}
	module := r.Module
	if module == "" {
		module = "ori.cli_bridge"
	}
	cmdArgs := make([]string, 0, 2+len(args))
	cmdArgs = append(cmdArgs, "-m", module)
	cmdArgs = append(cmdArgs, args...)
	cmd := exec.CommandContext(ctx, python, cmdArgs...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}, fmt.Errorf("bridge failed: %w", err)
	}
	return Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}, nil
}
