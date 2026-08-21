package cli

import (
	"fmt"
	"strings"

	"github.com/thexsa/peep/internal/ui"
)

// releaseNotes maps version strings to their "What's New" blurbs.
// Add a new entry for each release. The key is the version WITHOUT the "v" prefix.
// The blurb should be brief — detailed changelog is in CHANGELOG.md and on GitHub.
var releaseNotes = map[string]string{
	"0.7.0": `🔌 Connectivity check (-c) — TCP reachability test like telnet/netcat
🔍 Port scanning (peep portscan) — TCP connect scan, top 50 or all 65,535 ports
📜 Certificate discovery (peep find-certs) — protocol-aware cert scanning across ports
🤝 6 new protocols — POP3, IMAP, MSSQL, MySQL, PostgreSQL, XMPP
🏛️ CA store path — now shown after chain verification (pass or fail)`,
}

// releaseNotesURL is the base URL for release details on GitHub.
const releaseNotesURL = "https://github.com/thexsa/peep/releases/tag/v%s"

// showWhatsNew prints a brief "What's New" blurb for the given version.
// Called after a successful update. Returns true if notes were found and displayed.
func showWhatsNew(version string) bool {
	// Normalize: strip leading "v"
	v := strings.TrimPrefix(version, "v")

	notes, ok := releaseNotes[v]
	if !ok {
		return false
	}

	var lines []string
	lines = append(lines, ui.Theme.BoldStyle.Render("  What's New in v"+v))
	lines = append(lines, "")

	for _, line := range strings.Split(notes, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, "  "+line)
		}
	}

	lines = append(lines, "")
	lines = append(lines, ui.Theme.MutedStyle.Render(
		fmt.Sprintf("  Full details: %s", fmt.Sprintf(releaseNotesURL, v)),
	))
	lines = append(lines, ui.Theme.MutedStyle.Render(
		"  Changelog:    peep docs changelog (coming soon) or see CHANGELOG.md",
	))

	fmt.Println()
	fmt.Println(ui.ApplyBorder(lines, ui.SectionBorder))
	return true
}
