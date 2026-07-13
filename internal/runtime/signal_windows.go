// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package runtime

import "os"

func signalReload(_ *os.Process) error {
	return ErrUnsupportedPlatform
}
