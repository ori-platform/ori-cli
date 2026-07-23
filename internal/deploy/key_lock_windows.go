// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0
//go:build windows

package deploy

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

func lockFileNonBlocking(file *os.File) error {
	var overlapped windows.Overlapped
	err := windows.LockFileEx(
		windows.Handle(file.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		1,
		0,
		&overlapped,
	)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return errKeyStoreLocked
	}
	return err
}

func unlockFile(file *os.File) error {
	var overlapped windows.Overlapped
	return windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &overlapped)
}
