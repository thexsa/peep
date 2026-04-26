package ui

import (
	"fmt"
	"math/rand"
	"strings"

	"github.com/thexsa/peep/internal/analyzer"
)

// RenderBanner displays the header section with connection info.
func RenderBanner(host, port, ip, protocol string) string {
	lines := []string{
		Theme.BoldStyle.Render(fmt.Sprintf("  Peeping at %s:%s", host, port)),
		Theme.MutedStyle.Render(fmt.Sprintf("  IP: %s", ip)),
		Theme.MutedStyle.Render(fmt.Sprintf("  Protocol: %s", protocol)),
		Theme.SuccessStyle.Render(fmt.Sprintf("  %s handshake completed successfully", protocol)),
	}

	return ApplyBorder(lines, HeaderBorder)
}

// RenderSummaryHeader renders the banner + findings + verdict in a single header block.
func RenderSummaryHeader(host, port, ip, protocol string, report *analyzer.DiagnosticReport) string {
	var lines []string

	// Connection info
	lines = append(lines, Theme.BoldStyle.Render(fmt.Sprintf("  Peeping at %s:%s", host, port)))
	lines = append(lines, Theme.MutedStyle.Render(fmt.Sprintf("  IP: %s", ip)))
	lines = append(lines, Theme.MutedStyle.Render(fmt.Sprintf("  Protocol: %s", protocol)))
	lines = append(lines, Theme.SuccessStyle.Render(fmt.Sprintf("  %s handshake completed successfully", protocol)))

	// Prominent callout: server didn't include issuing CA
	if report.Chain.NoIssuingCAInResponse {
		lines = append(lines, "")
		lines = append(lines, Theme.ErrorStyle.Render("  ⚠ SERVER DID NOT INCLUDE THE ISSUING CA IN ITS RESPONSE"))
		lines = append(lines, wrapBlock(noIssuingCABannerSaying(), "    ", ContentWidth(4), Theme.MutedStyle)...)
	}

	// Quick verdict
	maxW := ContentWidth(2)
	lines = append(lines, "")
	lines = append(lines, fmt.Sprintf("  Verdict: %s", StatusBadge(report.OverallStatus)))
	saying := RandomSaying(report.OverallStatus)
	lines = append(lines, wrapBlock(saying, "  ", maxW, Theme.MutedStyle)...)

	// Quick findings summary
	if len(report.Warnings) > 0 {
		lines = append(lines, "")
		lines = append(lines, Theme.MutedStyle.Render(fmt.Sprintf("  Findings: %d issue(s) detected", len(report.Warnings))))
		for _, w := range report.Warnings {
			icon := StatusIcon(w.Severity)
			lines = append(lines, fmt.Sprintf("    %s %s", icon, w.Title))
		}
	} else {
		lines = append(lines, "")
		lines = append(lines, Theme.SuccessStyle.Render("  No issues found."))
	}

	// TLS version + cipher one-liner
	lines = append(lines, "")
	vGrade := StatusIcon(report.Handshake.VersionGrade)
	cGrade := StatusIcon(report.Handshake.CipherGrade)
	lines = append(lines, fmt.Sprintf("  %s TLS: %s", vGrade, report.Handshake.TLSVersion))
	lines = append(lines, fmt.Sprintf("  %s Cipher: %s", cGrade, report.Handshake.CipherSuite))

	return ApplyBorder(lines, HeaderBorder)
}

// RenderVersion displays the version banner.
func RenderVersion(version string) string {
	logo := Theme.BoldStyle.Render(fmt.Sprintf("peep %s", version))
	tagline := Theme.MutedStyle.Render("Your digital eyes for TLS diagnostics.")
	built := Theme.MutedStyle.Render("Built with pure Go — no OpenSSL required.")

	content := strings.Join([]string{logo, tagline, built}, "\n")
	return ApplyBorder([]string{content}, HeaderBorder)
}

var noIssuingCABannerSayings = []string{
	"How many times do we have to go over this? Include. The. Intermediate.",
	"Leaf cert, intermediate cert, done. It's two files. TWO. How is this still happening?",
	"We've been over this. The issuing CA goes IN the bundle. Not next to it. Not 'somewhere.' IN IT.",
	"It's not rocket science. It's literally cat leaf.crt intermediate.crt > fullchain.crt. That's it.",
	"At this point, I'm starting to think you're doing this on purpose.",
	"This is the third time today. Include the intermediate. PLEASE.",
	"The intermediate cert. In the chain. On the server. How is this still a conversation?",
	"One job. You had ONE job. Bundle the certs correctly. ONE. JOB.",
	"I explained this yesterday. And the day before. And the week before that.",
	"You know what's missing? The intermediate. You know what's always missing? The intermediate.",
	"I'm not mad. I'm just disappointed. Again. For the hundredth time.",
	"Somewhere, a CA published a 'How to install your cert' guide. Nobody read it. Clearly.",
}

func noIssuingCABannerSaying() string {
	return noIssuingCABannerSayings[rand.Intn(len(noIssuingCABannerSayings))]
}
