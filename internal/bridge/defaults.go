// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package bridge

const (
	// DefaultConfigPath is the operator-facing default for ori.yaml when no
	// path is supplied to config commands. The CLI delegates validation to the
	// runtime bridge rather than parsing the file itself.
	DefaultConfigPath = "ori.yaml"

	// DefaultSkillsDir is the operator-facing default skills directory when no
	// directory is supplied to skills commands. The runtime bridge owns skill
	// loading and validation semantics.
	DefaultSkillsDir = "skills"
)
