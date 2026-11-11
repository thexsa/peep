package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/thexsa/peep/internal/ui"
)

// releaseNotes maps version strings to their "What's New" blurbs.
// Add a new entry for each release. The key is the version WITHOUT the "v" prefix.
// The blurb should be brief — detailed changelog is in CHANGELOG.md and on GitHub.
var releaseNotes = map[string]string{
	"0.8.1": `* Guided Windows user-scope setup on first run & peep update (no admin required)
* Installs peep.exe to %LOCALAPPDATA%\Programs\peep + user PATH so 'peep <host>' just works
* Added 'peep update --install' + offline/GPO local fallback & local SHA-256 binary reuse
* Includes v0.8.0 deterministic missing-SAN, wire-chain, IPv6, and strict ASCII parity`,
	"0.8.0": `* Deterministic missing-SAN & CN-only detection across all OSes (including Windows)
* Wire-complete intermediate chain verification — defeats silent macOS/Windows AIA caching
* Protocol-aware cipher & TLS version enumeration across all 11 protocols in peep scan
* Strict 7-bit ASCII & zero-emoji guarantee (-p / --plain-text / --shades)
* Windows non-admin PowerShell installer (install.ps1), windows/arm64 builds & AIX install.sh`,
	"0.7.0": `* Connectivity check (-c) — TCP reachability test like telnet/netcat
* Port scanning (peep portscan) — TCP connect scan, top 50 or all 65,535 ports
* Certificate discovery (peep find-certs) — protocol-aware cert scanning across ports
* 6 new protocols — POP3, IMAP, MSSQL, MySQL, PostgreSQL, XMPP
* CA store path — now shown after chain verification (pass or fail)`,
}

// releaseNotesURL is the base URL for release details on GitHub.
const releaseNotesURL = "https://github.com/thexsa/peep/releases/tag/v%s"

// whatsnewCmd is a hidden subcommand used internally by `peep update`.
// After updating, the OLD binary execs the NEW binary with `whatsnew <version>`
// so that the NEW binary renders its own release notes.
var whatsnewCmd = &cobra.Command{
	Use:    "whatsnew [version]",
	Short:  "Show what's new in a version (used internally by peep update)",
	Hidden: true,
	Args:   cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		showWhatsNew(args[0])
	},
}

func init() {
	rootCmd.AddCommand(whatsnewCmd)
}

// showWhatsNew prints a brief "What's New" blurb for the given version.
func showWhatsNew(version string) {
	// Normalize: strip leading "v"
	v := strings.TrimPrefix(version, "v")

	notes, ok := releaseNotes[v]
	if !ok {
		return
	}

	if flagPlainText {
		ui.EnablePlainText()
	}

	var lines []string
	lines = append(lines, ui.Theme.BoldStyle.Render("  What's New in v"+v))
	lines = append(lines, "")

	for _, line := range strings.Split(notes, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, "    "+line)
		}
	}

	lines = append(lines, "")
	lines = append(lines, ui.Theme.MutedStyle.Render(
		fmt.Sprintf("  Full details: %s", fmt.Sprintf(releaseNotesURL, v)),
	))

	fmt.Println(ui.ApplyBorder(lines, ui.SectionBorder))
}
