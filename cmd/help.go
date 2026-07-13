// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

func installHelpTemplate(root *rootState, cmd *cobra.Command) {
	useColor := terminalColorEnabled(root.stdout)
	style := welcomeStyle(useColor)
	cobra.AddTemplateFunc("oriCommandLine", func(name string, description string) string {
		return oriCommandLine(style, name, description)
	})
	cmd.SetHelpTemplate(helpTemplate)
	cmd.SetUsageTemplate(usageTemplate)
}

func terminalColorEnabled(w io.Writer) bool {
	if !colorEnabled() {
		return false
	}
	file, ok := w.(*os.File)
	if !ok || file != os.Stdout {
		return false
	}
	stat, err := file.Stat()
	if err != nil {
		return false
	}
	return stat.Mode()&os.ModeCharDevice != 0
}

func oriCommandLine(style welcomeColors, name string, description string) string {
	const width = 12
	padding := width - len(name)
	if padding < 1 {
		padding = 1
	}
	return fmt.Sprintf("  %s%s%s%s%s", commandColor(style, name), name, style.reset, spaces(padding), description)
}

func commandColor(style welcomeColors, name string) string {
	switch name {
	case "completion":
		return style.blue
	case "config":
		return style.blue
	case "deploy":
		return style.orange
	case "doctor":
		return style.amber
	case "skills":
		return style.mint
	case "state":
		return style.dim
	case "token":
		return style.mint
	default:
		return style.white
	}
}

func spaces(count int) string {
	if count <= 0 {
		return ""
	}
	out := make([]byte, count)
	for index := range out {
		out[index] = ' '
	}
	return string(out)
}

const helpTemplate = `{{with (or .Long .Short)}}{{. | trimTrailingWhitespaces}}

{{end}}{{if or .Runnable .HasSubCommands}}{{.UsageString}}{{end}}`

const usageTemplate = `Usage:
  {{if .HasAvailableSubCommands}}{{.CommandPath}} [command]{{else}}{{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}

Available Commands:
{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}{{oriCommandLine .Name .Short}}
{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}
Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}

Global Flags:
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasHelpSubCommands}}

Additional help topics:
{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}{{oriCommandLine .Name .Short}}
{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}
Use "{{.CommandPath}} [command] --help" for more information about a command.{{end}}
`
