// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0
//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package deploy

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func lockFileNonBlocking(file *os.File) error {
	err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
		return errKeyStoreLocked
	}
	return err
}

func unlockFile(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_UN)
}
