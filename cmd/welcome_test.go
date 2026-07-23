// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWantsJSONOutputSuppressesWelcome(t *testing.T) {
	cases := [][]string{
		{"--json", "config", "validate"},
		{"--output", "json", "doctor", "runtime-health"},
		{"config", "show", "--output=json"},
	}

	for _, args := range cases {
		if !wantsJSONOutput(args) {
			t.Fatalf("wantsJSONOutput(%#v) = false, want true", args)
		}
	}
}

func TestWelcomeMarkerPathUsesXDGStateHome(t *testing.T) {
	stateHome := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateHome)

	path, err := welcomeMarkerPath()
	if err != nil {
		t.Fatalf("welcomeMarkerPath() error = %v", err)
	}
	want := filepath.Join(stateHome, "ori-cli", welcomeMarkerVersion)
	if path != want {
		t.Fatalf("welcomeMarkerPath() = %q, want %q", path, want)
	}
}

func TestShouldSkipWelcomeForNonInteractiveWriter(t *testing.T) {
	var stdout bytes.Buffer
	if !shouldSkipWelcome(nil, &stdout) {
		t.Fatal("expected noninteractive writer to skip welcome")
	}
}

func TestShouldSkipWelcomeInCI(t *testing.T) {
	t.Setenv("CI", "true")
	if !shouldSkipWelcome(nil, &bytes.Buffer{}) {
		t.Fatal("expected CI to skip welcome")
	}
}

func TestShouldSkipWelcomeEscapeHatch(t *testing.T) {
	t.Setenv("ORI_CLI_NO_WELCOME", "1")
	if !shouldSkipWelcome(nil, &bytes.Buffer{}) {
		t.Fatal("expected ORI_CLI_NO_WELCOME to skip welcome")
	}
}

func TestWelcomeAnimationRequiresColorTerminal(t *testing.T) {
	var output bytes.Buffer
	if shouldAnimateWelcome(&output, true) {
		t.Fatal("expected non-terminal writer to skip animation")
	}
	if shouldAnimateWelcome(&output, false) {
		t.Fatal("expected NO_COLOR mode to skip animation")
	}
}

func TestRenderWelcomePlainText(t *testing.T) {
	var stderr bytes.Buffer
	renderWelcome(&stderr, false)

	text := stderr.String()
	for _, want := range []string{
		"ORI",
		"Distributed infrastructure intelligence",
		"Reason. Act. Prevent.",
		"config validate",
		"doctor runtime-health",
		"skills list",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("welcome text missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "\x1b[") {
		t.Fatalf("plain welcome contains ANSI escape sequence: %q", text)
	}
}

func TestRenderWelcomeCentersInTerminal(t *testing.T) {
	const width = 80
	var out bytes.Buffer
	renderWelcomeAt(&out, false, width)

	logoPad := strings.Repeat(" ", (width-welcomeLogoWidth())/2)
	for index, row := range welcomeLogoRows {
		want := logoPad + row.o + row.r + row.i
		if !strings.Contains(out.String(), want+"\n") {
			t.Fatalf("logo row %d not block-centered at width %d: want %q in:\n%s",
				index, width, want, out.String())
		}
	}

	for _, text := range []string{"ORI  Distributed infrastructure intelligence", "Reason. Act. Prevent."} {
		want := strings.Repeat(" ", (width-len(text))/2) + text
		if !strings.Contains(out.String(), want) {
			t.Fatalf("tagline %q not centered at width %d:\n%s", text, width, out.String())
		}
	}
}

func TestRenderWelcomeCentersCommandHintsAsTable(t *testing.T) {
	const width = 80
	var out bytes.Buffer
	renderWelcomeAt(&out, false, width)

	commandWidth := len("doctor runtime-health")
	wantLines := []struct {
		command     string
		description string
	}{
		{"config validate", "check runtime posture"},
		{"doctor runtime-health", "inspect a running device"},
		{"skills list", "see installed Ori skills"},
	}
	lineWidth := commandWidth + 4 + len("inspect a running device")
	leftPad := strings.Repeat(" ", (width-lineWidth)/2)
	for _, want := range wantLines {
		line := leftPad + want.command + strings.Repeat(" ", commandWidth-len(want.command)+4) + want.description
		if !strings.Contains(out.String(), line+"\n") {
			t.Fatalf("hint line not centered as table, missing %q in:\n%s", line, out.String())
		}
	}
}

func TestWelcomeLogoStaysAlignedWithColor(t *testing.T) {
	var colored, plain bytes.Buffer
	renderWelcome(&colored, true)
	renderWelcome(&plain, false)

	coloredLines := strings.Split(colored.String(), "\n")
	plainLines := strings.Split(plain.String(), "\n")
	if len(coloredLines) != len(plainLines) {
		t.Fatalf("line count differs: colored %d, plain %d", len(coloredLines), len(plainLines))
	}
	for index, line := range coloredLines {
		if stripANSI(line) != plainLines[index] {
			t.Fatalf("line %d misaligned once color is stripped:\ncolored: %q\nplain:   %q",
				index, stripANSI(line), plainLines[index])
		}
	}
}

func TestWelcomeAnimationUsesBoundedRevealAndColorRamp(t *testing.T) {
	const width = 80
	var output bytes.Buffer
	var delays []time.Duration

	renderWelcomeAnimatedAt(
		&output,
		width,
		func(delay time.Duration) {
			delays = append(delays, delay)
		},
	)

	wantDelayCount := (len(welcomeLogoRows) - 1) * 2
	if len(delays) != wantDelayCount {
		t.Fatalf("delay count = %d, want %d", len(delays), wantDelayCount)
	}
	var total time.Duration
	for _, delay := range delays {
		total += delay
	}
	if total >= welcomeAnimationMax {
		t.Fatalf("animation delay budget = %s, must be under %s", total, welcomeAnimationMax)
	}
	if !strings.Contains(output.String(), fmt.Sprintf("\x1b[%dA", len(welcomeLogoRows))) {
		t.Fatalf("animation does not return to the first logo row: %q", output.String())
	}
	if count := strings.Count(output.String(), "\x1b[2K"); count != len(welcomeLogoRows) {
		t.Fatalf("row rewrite count = %d, want %d", count, len(welcomeLogoRows))
	}
	for _, want := range []string{
		"\x1b[38;2;64;25;0m",
		"\x1b[1;38;2;255;98;0m",
		"Distributed infrastructure intelligence",
		"Reason. Act. Prevent.",
	} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("animated welcome missing %q", want)
		}
	}
}
