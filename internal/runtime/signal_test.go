// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package runtime

import (
	"errors"
	"os/exec"
	"testing"
	"time"
)

func TestReloadSkillsRejectsInvalidPID(t *testing.T) {
	err := ReloadSkills(-1)
	if err == nil {
		t.Fatal("expected error for negative PID")
	}
}

func TestReloadSkillsRejectsNonExistentProcess(t *testing.T) {
	// PID 99999 is extremely unlikely to exist in a test environment.
	err := ReloadSkills(99999)
	if err == nil {
		t.Fatal("expected error for non-existent PID")
	}
	if errors.Is(err, ErrUnsupportedPlatform) {
		t.Skip("unsupported platform")
	}
}

func TestReloadSkillsSendsSignalToChildProcess(t *testing.T) {
	// Start a long-running child process. SIGHUP terminates it by default,
	// so we can verify the signal was delivered by watching it exit quickly.
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start child process: %v", err)
	}

	if err := ReloadSkills(cmd.Process.Pid); err != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("failed to signal child process: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case <-done:
		// Child exited after SIGHUP — signal was delivered.
	case <-time.After(2 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("child process did not exit after SIGHUP")
	}
}
