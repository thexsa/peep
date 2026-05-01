package main

import (
	"os"
	"runtime"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"github.com/thexsa/peep/internal/cli"
)

func init() {
	// AIX terminals don't respond to termenv's OSC color queries,
	// causing the program to hang during terminal capability detection.
	// Force ANSI color profile on AIX to bypass the query entirely.
	if runtime.GOOS == "aix" {
		lipgloss.DefaultRenderer().SetColorProfile(termenv.ANSI)
	}
}

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
