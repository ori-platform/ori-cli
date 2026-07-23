// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/term"
)

const welcomeMarkerVersion = "welcome-v1"

const (
	welcomeRevealDelay   = 30 * time.Millisecond
	welcomeBrightenDelay = 18 * time.Millisecond
	welcomeAnimationMax  = 250 * time.Millisecond
)

var ansiEscapePattern = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func maybeShowFirstRunWelcome(args []string, stdout io.Writer, stderr io.Writer) {
	if shouldSkipWelcome(args, stdout) {
		return
	}
	markerPath, err := welcomeMarkerPath()
	if err != nil {
		return
	}
	if _, err := os.Stat(markerPath); err == nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(markerPath), 0o700); err != nil {
		return
	}
	useColor := colorEnabled()
	if shouldAnimateWelcome(stderr, useColor) {
		renderWelcomeAnimatedAt(stderr, terminalWidth(stderr), time.Sleep)
	} else {
		renderWelcome(stderr, useColor)
	}
	if err := os.WriteFile(markerPath, []byte("shown\n"), 0o600); err != nil {
		return
	}
}

func shouldAnimateWelcome(w io.Writer, useColor bool) bool {
	if !useColor {
		return false
	}
	file, ok := w.(*os.File)
	if !ok {
		return false
	}
	stat, err := file.Stat()
	if err != nil {
		return false
	}
	return stat.Mode()&os.ModeCharDevice != 0
}

func shouldSkipWelcome(args []string, stdout io.Writer) bool {
	if os.Getenv("ORI_CLI_NO_WELCOME") != "" || os.Getenv("CI") != "" {
		return true
	}
	if wantsJSONOutput(args) {
		return true
	}
	file, ok := stdout.(*os.File)
	if !ok || file != os.Stdout {
		return true
	}
	stat, err := file.Stat()
	if err != nil {
		return true
	}
	return stat.Mode()&os.ModeCharDevice == 0
}

func wantsJSONOutput(args []string) bool {
	for index, arg := range args {
		if arg == "--json" || arg == "-json" {
			return true
		}
		if arg == "--output=json" {
			return true
		}
		if arg == "--output" && index+1 < len(args) && args[index+1] == "json" {
			return true
		}
	}
	return false
}

func welcomeMarkerPath() (string, error) {
	if stateHome := os.Getenv("XDG_STATE_HOME"); strings.TrimSpace(stateHome) != "" {
		return filepath.Join(stateHome, "ori-cli", welcomeMarkerVersion), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "state", "ori-cli", welcomeMarkerVersion), nil
}

func colorEnabled() bool {
	return os.Getenv("NO_COLOR") == ""
}

// welcomeLogoRows is "ori" in the figlet slant font (the style used by the
// Oh My Zsh banner), split per letter so each glyph takes one brand color.
type welcomeLogoRow struct {
	o, r, i string
}

var welcomeLogoRows = []welcomeLogoRow{
	{"       ", "       ", "_"},
	{"  ____ ", " _____", "(_)"},
	{` / __ \`, "/ ___/", " /"},
	{"/ /_/ /", " /", "  / /"},
	{`\____/`, "_/", "  /_/"},
}

func renderWelcome(w io.Writer, useColor bool) {
	renderWelcomeAt(w, useColor, terminalWidth(w))
}

func renderWelcomeAt(w io.Writer, useColor bool, width int) {
	style := welcomeStyle(useColor)
	logoPad := centerPad(width, welcomeLogoWidth())
	fmt.Fprintln(w)
	for _, row := range welcomeLogoRows {
		fmt.Fprintln(w, formatWelcomeLogoRow(logoPad, style, row))
	}
	renderWelcomeBody(w, style, width)
}

func renderWelcomeAnimatedAt(
	w io.Writer,
	width int,
	sleep func(time.Duration),
) {
	style := welcomeStyle(true)
	dimStyle := welcomeDimLogoStyle()
	logoPad := centerPad(width, welcomeLogoWidth())

	fmt.Fprintln(w)
	for index, row := range welcomeLogoRows {
		fmt.Fprintln(w, formatWelcomeLogoRow(logoPad, dimStyle, row))
		if index+1 < len(welcomeLogoRows) {
			sleep(welcomeRevealDelay)
		}
	}

	fmt.Fprintf(w, "\x1b[%dA", len(welcomeLogoRows))
	for index, row := range welcomeLogoRows {
		fmt.Fprint(w, "\r\x1b[2K")
		fmt.Fprintln(w, formatWelcomeLogoRow(logoPad, style, row))
		if index+1 < len(welcomeLogoRows) {
			sleep(welcomeBrightenDelay)
		}
	}
	renderWelcomeBody(w, style, width)
}

func formatWelcomeLogoRow(
	logoPad string,
	style welcomeColors,
	row welcomeLogoRow,
) string {
	return logoPad +
		style.orange + row.o + style.reset +
		style.mint + row.r + style.reset +
		style.blue + row.i + style.reset
}

func renderWelcomeBody(w io.Writer, style welcomeColors, width int) {
	fmt.Fprintln(w)
	tagline := "ORI  Distributed infrastructure intelligence"
	motto := "Reason. Act. Prevent."
	fmt.Fprintln(w, centerPad(width, len(tagline))+style.white+"ORI"+style.reset+"  "+style.mint+"Distributed infrastructure intelligence"+style.reset)
	fmt.Fprintln(w, centerPad(width, len(motto))+style.dim+motto+style.reset)
	fmt.Fprintln(w)
	renderWelcomeHints(w, style, width, []welcomeHint{
		{style.blue, "config validate", "check runtime posture"},
		{style.amber, "doctor runtime-health", "inspect a running device"},
		{style.mint, "skills list", "see installed Ori skills"},
	})
	fmt.Fprintln(w)
}

type welcomeHint struct {
	color       string
	command     string
	description string
}

func renderWelcomeHints(w io.Writer, style welcomeColors, width int, hints []welcomeHint) {
	const gap = 4
	commandWidth := 0
	for _, hint := range hints {
		if len(hint.command) > commandWidth {
			commandWidth = len(hint.command)
		}
	}
	lineWidth := 0
	for _, hint := range hints {
		if visible := commandWidth + gap + len(hint.description); visible > lineWidth {
			lineWidth = visible
		}
	}
	leftPad := centerPad(width, lineWidth)
	for _, hint := range hints {
		commandPadding := commandWidth - len(hint.command) + gap
		fmt.Fprintln(
			w,
			leftPad+
				hint.color+hint.command+style.reset+
				strings.Repeat(" ", commandPadding)+
				style.dim+hint.description+style.reset,
		)
	}
}

func stripANSI(text string) string {
	return ansiEscapePattern.ReplaceAllString(text, "")
}

// welcomeLogoWidth is the widest visible logo row; the whole logo block is
// centered by this width so the letterforms keep their relative alignment.
func welcomeLogoWidth() int {
	widest := 0
	for _, row := range welcomeLogoRows {
		if width := len(row.o) + len(row.r) + len(row.i); width > widest {
			widest = width
		}
	}
	return widest
}

// terminalWidth reports the column count of w, or 0 when w is not a
// terminal (in which case output stays left-aligned).
func terminalWidth(w io.Writer) int {
	file, ok := w.(*os.File)
	if !ok {
		return 0
	}
	width, _, err := term.GetSize(int(file.Fd()))
	if err != nil || width < 0 {
		return 0
	}
	return width
}

func centerPad(terminalWidth, visibleWidth int) string {
	if terminalWidth <= visibleWidth {
		return ""
	}
	return strings.Repeat(" ", (terminalWidth-visibleWidth)/2)
}

type welcomeColors struct {
	reset  string
	orange string
	mint   string
	blue   string
	amber  string
	white  string
	dim    string
}

// Values come from the Ori design-system tokens in
// ori-energy/apps/web/src/demo/demo.css (--mktg-orange, --ori-mint,
// --tier-a, --tier-c, --muted).
func welcomeStyle(useColor bool) welcomeColors {
	if !useColor {
		return welcomeColors{}
	}
	return welcomeColors{
		reset:  "\x1b[0m",
		orange: "\x1b[1;38;2;255;98;0m",    // #ff6200
		mint:   "\x1b[1;38;2;0;191;165m",   // #00bfa5
		blue:   "\x1b[1;38;2;76;155;232m",  // #4c9be8
		amber:  "\x1b[1;38;2;232;154;60m",  // #e89a3c
		white:  "\x1b[1;38;2;245;248;250m", // near-white
		dim:    "\x1b[38;2;140;160;179m",   // #8ca0b3
	}
}

func welcomeDimLogoStyle() welcomeColors {
	return welcomeColors{
		reset:  "\x1b[0m",
		orange: "\x1b[38;2;64;25;0m",
		mint:   "\x1b[38;2;0;48;41m",
		blue:   "\x1b[38;2;19;39;58m",
	}
}
