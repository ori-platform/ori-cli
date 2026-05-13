// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"encoding/json"
	"fmt"
	"io"
)

type ErrorPayload struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
}

func JSON(w io.Writer, payload any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}

func Text(w io.Writer, format string, args ...any) {
	fmt.Fprintf(w, format, args...)
}

func Error(w io.Writer, jsonMode bool, message string) {
	if jsonMode {
		_ = JSON(w, ErrorPayload{OK: false, Error: message})
		return
	}
	fmt.Fprintln(w, "Error: "+message)
}
