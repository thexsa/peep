package ui

import (
	"fmt"

	"github.com/thexsa/peep/internal/analyzer"
)

// RenderOCSPResult renders the OCSP check result.
func RenderOCSPResult(result analyzer.OCSPResult) string {
	header := Theme.BoldStyle.Render("OCSP REVOCATION CHECK")

	var lines []string
	lines = append(lines, header)
	lines = append(lines, "")

	switch result.Status {
	case analyzer.OCSPGood:
		lines = append(lines, renderKV("Status", Theme.SuccessStyle.Render("Good — not revoked")))
	case analyzer.OCSPRevoked:
		lines = append(lines, renderKV("Status", Theme.ErrorStyle.Render("REVOKED")))
		if !result.RevokedAt.IsZero() {
			lines = append(lines, renderKV("Revoked At", result.RevokedAt.Format("Jan 02, 2006 15:04:05 MST")))
		}
		if result.RevokeReason != "" {
			lines = append(lines, renderKV("Reason", result.RevokeReason))
		}
	case analyzer.OCSPUnknown:
		lines = append(lines, renderKV("Status", Theme.WarningStyle.Render("Unknown")))
	case analyzer.OCSPError:
		lines = append(lines, renderKV("Status", Theme.WarningStyle.Render("Error checking")))
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

	return ApplyBorder(lines, SectionBorder) + "\n"
}

// RenderCTLogResult renders the Certificate Transparency log check.
func RenderCTLogResult(result analyzer.CTLogResult) string {
	header := Theme.BoldStyle.Render("CERTIFICATE TRANSPARENCY")

	var lines []string
	lines = append(lines, header)
	lines = append(lines, "")

	if result.Error != "" {
		lines = append(lines, renderKV("Status", Theme.WarningStyle.Render("Could not check CT logs")))
		lines = append(lines, renderKV("Detail", Theme.MutedStyle.Render(result.Error)))
	} else if result.Found {
		lines = append(lines, renderKV("Status", Theme.SuccessStyle.Render("Found in CT logs")))
		lines = append(lines, renderKV("Entries", fmt.Sprintf("%d log entries found", result.LogCount)))
		if result.FirstSeen != "" {
			lines = append(lines, renderKV("First Seen", result.FirstSeen))
		}
	} else {
		lines = append(lines, renderKV("Status", Theme.WarningStyle.Render("Not in CT logs — either brand new or someone's hiding something")))
	}

	return ApplyBorder(lines, SectionBorder) + "\n"
}

// RenderCipherEnum renders the cipher suite enumeration results.
func RenderCipherEnum(result analyzer.CipherEnumResult) string {
	header := Theme.BoldStyle.Render("SUPPORTED CIPHER SUITES & TLS VERSIONS")

	var lines []string
	lines = append(lines, header)
	lines = append(lines, "")

	// TLS Version support
	lines = append(lines, Theme.BoldStyle.Render("TLS Versions:"))
	for _, v := range result.TLSVersions {
		status := Theme.MutedStyle.Render("not supported")
		if v.Supported {
			status = StatusIcon(v.Grade)
		}
		lines = append(lines, fmt.Sprintf("  %-10s %s", v.Version, status))
	}

	// Cipher suites
	lines = append(lines, "")
	lines = append(lines, Theme.BoldStyle.Render(fmt.Sprintf("Cipher Suites (%d supported):", len(result.SupportedSuites))))

	// Group by grade
	var bad, good []analyzer.CipherSuiteInfo
	for _, suite := range result.SupportedSuites {
		if suite.Grade == analyzer.WrittenInCrayon {
			bad = append(bad, suite)
		} else {
			good = append(good, suite)
		}
	}

	if len(bad) > 0 {
		lines = append(lines, "")
		lines = append(lines, Theme.ErrorStyle.Render(fmt.Sprintf("  Insecure (%d):", len(bad))))
		for _, suite := range bad {
			lines = append(lines, fmt.Sprintf("    %s %s",
				Theme.ErrorStyle.Render("x"),
				Theme.MutedStyle.Render(suite.Name)))
		}
	}

	if len(good) > 0 {
		lines = append(lines, "")
		lines = append(lines, Theme.SuccessStyle.Render(fmt.Sprintf("  Secure (%d):", len(good))))
		for _, suite := range good {
			lines = append(lines, fmt.Sprintf("    %s %s [%s]",
				Theme.SuccessStyle.Render("+"),
				suite.Name,
				Theme.MutedStyle.Render(suite.Version)))
		}
	}

	if len(result.SupportedSuites) == 0 {
		lines = append(lines, Theme.MutedStyle.Render("  No cipher suites detected"))
	}

	// Summary
	lines = append(lines, "")
	if len(bad) > 0 {
		lines = append(lines, Theme.ErrorStyle.Render(fmt.Sprintf("%d insecure cipher suite(s) detected. Disable them. Yesterday.", len(bad))))
	} else if len(good) > 0 {
		lines = append(lines, Theme.SuccessStyle.Render("All supported cipher suites are secure."))
	}

	return ApplyBorder(lines, SectionBorder) + "\n"
}
