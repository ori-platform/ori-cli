// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

// Package runtime provides local process interactions with a running Ori
// runtime. It does not replace the runtime bridge; it implements CLI commands
// that are explicitly process-oriented rather than validation-oriented.
package runtime

import (
	"fmt"
	"os"
	"runtime"
)

// ErrUnsupportedPlatform is returned when a process signal operation is not
// available on the current operating system.
var ErrUnsupportedPlatform = fmt.Errorf("process signal operations are not supported on %s", runtime.GOOS)

// ReloadSkills sends a SIGHUP signal to the runtime process identified by pid.
// The runtime interprets SIGHUP as a request to reload skills without
// restarting the process.
func ReloadSkills(pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("cannot find runtime process %d: %w", pid, err)
	}
	return signalReload(proc)
}
