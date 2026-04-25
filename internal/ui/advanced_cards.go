package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/thexsa/peep/internal/analyzer"
)

// RenderOCSPResult renders the OCSP check result.
func RenderOCSPResult(result analyzer.OCSPResult, personality analyzer.Personality) string {
	header := Theme.TitleStyle.Render("🔍 OCSP Revocation Check")

	var lines []string
	lines = append(lines, header)
	lines = append(lines, "")

	switch result.Status {
	case analyzer.OCSPGood:
		lines = append(lines, renderKV("Status", Theme.SuccessStyle.Render("✅ Good — not revoked")))
	case analyzer.OCSPRevoked:
		lines = append(lines, renderKV("Status", Theme.ErrorStyle.Render("❌ REVOKED")))
		if !result.RevokedAt.IsZero() {
			lines = append(lines, renderKV("Revoked At", result.RevokedAt.Format("Jan 02, 2006 15:04:05 MST")))
		}
		if result.RevokeReason != "" {
			lines = append(lines, renderKV("Reason", result.RevokeReason))
		}
	case analyzer.OCSPUnknown:
		lines = append(lines, renderKV("Status", Theme.WarningStyle.Render("⚠️  Unknown")))
	case analyzer.OCSPError:
		lines = append(lines, renderKV("Status", Theme.WarningStyle.Render("⚠️  Error checking")))
	}

	if result.Error != "" && result.Status != analyzer.OCSPGood {
		lines = append(lines, renderKV("Detail", Theme.MutedStyle.Render(result.Error)))
	}

	if result.ResponderURL != "" {
		lines = append(lines, renderKV("Responder", Theme.MutedStyle.Render(result.ResponderURL)))
	}

	if !result.ThisUpdate.IsZero() {
		lines = append(lines, renderKV("Last Check", result.ThisUpdate.Format("Jan 02, 2006 15:04:05 MST")))
	}
	if !result.NextUpdate.IsZero() {
		lines = append(lines, renderKV("Next Update", result.NextUpdate.Format("Jan 02, 2006 15:04:05 MST")))
	}

	content := lipgloss.JoinVertical(lipgloss.Left, lines...)
	return Theme.CardStyle.Render(content)
}

// RenderCTLogResult renders the Certificate Transparency log check.
func RenderCTLogResult(result analyzer.CTLogResult, personality analyzer.Personality) string {
	header := Theme.TitleStyle.Render("📜 Certificate Transparency")

	var lines []string
	lines = append(lines, header)
	lines = append(lines, "")

	if result.Error != "" {
		lines = append(lines, renderKV("Status", Theme.WarningStyle.Render("⚠️  Could not check CT logs")))
		lines = append(lines, renderKV("Detail", Theme.MutedStyle.Render(result.Error)))
	} else if result.Found {
		lines = append(lines, renderKV("Status", Theme.SuccessStyle.Render("✅ Found in CT logs")))
		lines = append(lines, renderKV("Entries", fmt.Sprintf("%d log entries found", result.LogCount)))
		if result.FirstSeen != "" {
			lines = append(lines, renderKV("First Seen", result.FirstSeen))
		}
	} else {
		msg := "⚠️  Not found in CT logs"
		if personality == analyzer.Rude {
			msg = "⚠️  Not in CT logs — either it's brand new or someone's hiding something"
		}
		lines = append(lines, renderKV("Status", Theme.WarningStyle.Render(msg)))
	}

	content := lipgloss.JoinVertical(lipgloss.Left, lines...)
	return Theme.CardStyle.Render(content)
}

// RenderCipherEnum renders the cipher suite enumeration results.
func RenderCipherEnum(result analyzer.CipherEnumResult, personality analyzer.Personality) string {
	header := Theme.TitleStyle.Render("🔐 Supported Cipher Suites & TLS Versions")

	var lines []string
	lines = append(lines, header)
	lines = append(lines, "")

	// TLS Version support
	lines = append(lines, Theme.BoldStyle.Render("TLS Versions:"))
	for _, v := range result.TLSVersions {
		status := Theme.MutedStyle.Render("not supported")
		if v.Supported {
			status = StatusBadge(v.Grade)
		}
		lines = append(lines, fmt.Sprintf("  %-10s %s", v.Version, status))
	}

	// Cipher suites
	lines = append(lines, "")
	lines = append(lines, Theme.BoldStyle.Render(fmt.Sprintf("Cipher Suites (%d supported):", len(result.SupportedSuites))))

	// Group by grade
	var stormy, clear []analyzer.CipherSuiteInfo
	for _, suite := range result.SupportedSuites {
		if suite.Grade == analyzer.Stormy {
			stormy = append(stormy, suite)
		} else {
			clear = append(clear, suite)
		}
	}

	if len(stormy) > 0 {
		lines = append(lines, "")
		lines = append(lines, Theme.ErrorStyle.Render(fmt.Sprintf("  ❌ Insecure Suites (%d):", len(stormy))))
		for _, suite := range stormy {
			lines = append(lines, fmt.Sprintf("    %s %s",
				Theme.ErrorStyle.Render("✗"),
				Theme.MutedStyle.Render(suite.Name)))
		}
	}

	if len(clear) > 0 {
		lines = append(lines, "")
		lines = append(lines, Theme.SuccessStyle.Render(fmt.Sprintf("  ✅ Secure Suites (%d):", len(clear))))
		for _, suite := range clear {
			lines = append(lines, fmt.Sprintf("    %s %s [%s]",
				Theme.SuccessStyle.Render("✓"),
				suite.Name,
				Theme.MutedStyle.Render(suite.Version)))
		}
	}

	if len(result.SupportedSuites) == 0 {
		lines = append(lines, Theme.MutedStyle.Render("  No cipher suites detected (server may have closed connections)"))
	}

	// Summary
	lines = append(lines, "")
	if len(stormy) > 0 {
		msg := fmt.Sprintf("⚠️  %d insecure cipher suite(s) detected!", len(stormy))
		if personality == analyzer.Rude {
			msg += " Disable them. Yesterday."
		}
		lines = append(lines, Theme.ErrorStyle.Render(msg))
	} else if len(clear) > 0 {
		lines = append(lines, Theme.SuccessStyle.Render("All supported cipher suites are secure. 👍"))
	}

	content := strings.Join(lines, "\n")
	return Theme.CardStyle.Render(content)
}
