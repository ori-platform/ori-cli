// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package runtime

import (
	"fmt"
	"os"
	"syscall"
)

func signalReload(proc *os.Process) error {
	if err := proc.Signal(syscall.SIGHUP); err != nil {
		return fmt.Errorf("failed to send SIGHUP to runtime process %d: %w", proc.Pid, err)
	}
	return nil
}
