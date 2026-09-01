// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package capture

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// TerminalAsker runs the ceremony over an ordinary reader and writer.
//
// It deliberately does not require a terminal. Capture is data entry, not an
// authority operation: nothing it produces is trusted until it is signed, and
// an installer who wanted to fabricate answers could author the JSON directly.
// The operation that does need a terminal is the runtime's consent, which the
// runtime takes on `/dev/tty` itself and which no part of this tool can supply.
type TerminalAsker struct {
	In  io.Reader
	Out io.Writer

	reader *bufio.Reader
}

// NewTerminalAsker reads answers from in and writes prompts to out.
func NewTerminalAsker(in io.Reader, out io.Writer) *TerminalAsker {
	return &TerminalAsker{In: in, Out: out, reader: bufio.NewReader(in)}
}

// Ask puts one question and returns the line given back.
func (t *TerminalAsker) Ask(prompt string) (string, error) {
	fmt.Fprintf(t.Out, "\n%s\n> ", prompt)
	line, err := t.reader.ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("the ceremony ended before %q was answered", prompt)
	}
	return strings.TrimSpace(line), nil
}

// Choose offers exactly the options given and accepts nothing else.
//
// An unrecognised answer is re-asked rather than resolved to the nearest
// option: a commissioning answer nobody quite gave is the failure this
// ceremony exists to prevent.
func (t *TerminalAsker) Choose(prompt string, options []string) (string, error) {
	if len(options) == 0 {
		return "", fmt.Errorf("nothing to choose from for %q", prompt)
	}
	for {
		fmt.Fprintf(t.Out, "\n%s\n", prompt)
		for i, option := range options {
			fmt.Fprintf(t.Out, "  %d) %s\n", i+1, option)
		}
		fmt.Fprint(t.Out, "> ")

		line, err := t.reader.ReadString('\n')
		if err != nil && line == "" {
			return "", fmt.Errorf("the ceremony ended before %q was answered", prompt)
		}
		answer := strings.TrimSpace(line)

		if n, convErr := strconv.Atoi(answer); convErr == nil {
			if n >= 1 && n <= len(options) {
				return options[n-1], nil
			}
			fmt.Fprintf(t.Out, "  %d is not one of the %d choices.\n", n, len(options))
			continue
		}
		for _, option := range options {
			if strings.EqualFold(answer, option) {
				return option, nil
			}
		}
		fmt.Fprintf(t.Out, "  %q is not one of the choices.\n", answer)
	}
}
