package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
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

	content := lipgloss.JoinVertical(lipgloss.Left, lines...)
	return Theme.HeaderBoxStyle.Render(content)
}

// RenderSummaryHeader renders the banner + findings + verdict in a single header block.
func RenderSummaryHeader(host, port, ip, protocol string, report *analyzer.DiagnosticReport) string {
	var lines []string

	// Connection info
	lines = append(lines, Theme.BoldStyle.Render(fmt.Sprintf("  Peeping at %s:%s", host, port)))
	lines = append(lines, Theme.MutedStyle.Render(fmt.Sprintf("  IP: %s", ip)))
	lines = append(lines, Theme.MutedStyle.Render(fmt.Sprintf("  Protocol: %s", protocol)))
	lines = append(lines, Theme.SuccessStyle.Render(fmt.Sprintf("  %s handshake completed successfully", protocol)))

	// Quick verdict
	lines = append(lines, "")
	lines = append(lines, fmt.Sprintf("  Verdict: %s", StatusBadge(report.OverallStatus)))
	lines = append(lines, fmt.Sprintf("  %s", Theme.MutedStyle.Render(RandomSaying(report.OverallStatus))))

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

	content := lipgloss.JoinVertical(lipgloss.Left, lines...)
	return Theme.HeaderBoxStyle.Render(content)
}

// RenderVersion displays the version banner.
func RenderVersion(version string) string {
	logo := Theme.BoldStyle.Render(fmt.Sprintf("peep %s", version))
	tagline := Theme.MutedStyle.Render("Your digital eyes for TLS diagnostics.")
	built := Theme.MutedStyle.Render("Built with pure Go — no OpenSSL required.")

	content := strings.Join([]string{logo, tagline, built}, "\n")
	return Theme.HeaderBoxStyle.Render(content)
}
