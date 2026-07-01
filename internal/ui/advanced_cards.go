package ui

import (
	"fmt"
	"strings"

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

// RenderOCSPStapleResult renders the stapled OCSP response check.
func RenderOCSPStapleResult(result analyzer.OCSPStapleResult) string {
	header := Theme.BoldStyle.Render("OCSP STAPLE CHECK")

	var lines []string
	lines = append(lines, header)
	lines = append(lines, "")

	if !result.Present {
		lines = append(lines, renderKV("Stapled", Theme.WarningStyle.Render("No — server did not staple an OCSP response")))
		return ApplyBorder(lines, SectionBorder) + "\n"
	}

	lines = append(lines, renderKV("Stapled", Theme.SuccessStyle.Render("Yes")))

	switch result.Status {
	case analyzer.OCSPGood:
		lines = append(lines, renderKV("Status", Theme.SuccessStyle.Render("Good — certificate is valid")))
	case analyzer.OCSPRevoked:
		lines = append(lines, renderKV("Status", Theme.ErrorStyle.Render("REVOKED — stapled response says cert is revoked!")))
	case analyzer.OCSPUnknown:
		lines = append(lines, renderKV("Status", Theme.WarningStyle.Render("Unknown")))
	case analyzer.OCSPError:
		lines = append(lines, renderKV("Status", Theme.WarningStyle.Render("Error parsing staple")))
		if result.Error != "" {
			lines = append(lines, renderKV("Detail", Theme.MutedStyle.Render(result.Error)))
		}
	}

	if !result.ProducedAt.IsZero() {
		lines = append(lines, renderKV("Produced At", result.ProducedAt.Format("Jan 02, 2006 15:04:05 MST")))
	}
	if !result.ThisUpdate.IsZero() {
		lines = append(lines, renderKV("This Update", result.ThisUpdate.Format("Jan 02, 2006 15:04:05 MST")))
	}
	if !result.NextUpdate.IsZero() {
		label := "Next Update"
		value := result.NextUpdate.Format("Jan 02, 2006 15:04:05 MST")
		if result.IsStale {
			value += Theme.ErrorStyle.Render(" (STALE — past due!)")
		}
		lines = append(lines, renderKV(label, value))
	}

	return ApplyBorder(lines, SectionBorder) + "\n"
}

// RenderCRLResult renders the CRL revocation check result.
func RenderCRLResult(result analyzer.CRLResult) string {
	header := Theme.BoldStyle.Render("CRL REVOCATION CHECK")

	var lines []string
	lines = append(lines, header)
	lines = append(lines, "")

	if !result.Available {
		lines = append(lines, renderKV("Status", Theme.MutedStyle.Render("No CRL distribution points in certificate")))
		return ApplyBorder(lines, SectionBorder) + "\n"
	}

	lines = append(lines, renderKV("CRL Endpoint", Theme.MutedStyle.Render(result.CRLEndpoint)))

	if !result.Fetched {
		lines = append(lines, renderKV("Fetch", Theme.WarningStyle.Render("Failed")))
		if result.FetchError != "" {
			lines = append(lines, renderKV("Detail", Theme.MutedStyle.Render(result.FetchError)))
		}
		return ApplyBorder(lines, SectionBorder) + "\n"
	}

	lines = append(lines, renderKV("Fetch", Theme.SuccessStyle.Render(fmt.Sprintf("OK (%d bytes, %d entries)", result.CRLSize, result.EntryCount))))

	if result.IsRevoked {
		lines = append(lines, renderKV("Status", Theme.ErrorStyle.Render("REVOKED — certificate found on CRL!")))
		if !result.RevokedAt.IsZero() {
			lines = append(lines, renderKV("Revoked At", result.RevokedAt.Format("Jan 02, 2006 15:04:05 MST")))
		}
		if result.RevokeReason != "" {
			lines = append(lines, renderKV("Reason", result.RevokeReason))
		}
	} else {
		lines = append(lines, renderKV("Status", Theme.SuccessStyle.Render("Not revoked — serial not found on CRL")))
	}

	if !result.ThisUpdate.IsZero() {
		lines = append(lines, renderKV("Published", result.ThisUpdate.Format("Jan 02, 2006 15:04:05 MST")))
	}
	if !result.NextUpdate.IsZero() {
		value := result.NextUpdate.Format("Jan 02, 2006 15:04:05 MST")
		if result.IsStale {
			value += Theme.ErrorStyle.Render(" (STALE — past due!)")
		}
		lines = append(lines, renderKV("Next Update", value))
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

// cipherSassMap returns a sarcastic annotation for known-insecure cipher components.
func cipherSass(name string) string {
	upper := strings.ToUpper(name)
	switch {
	case strings.Contains(upper, "NULL"):
		return "← literally no encryption. Impressive commitment to insecurity."
	case strings.Contains(upper, "EXPORT"):
		return "← designed to be breakable by '90s governments. Now breakable by everyone."
	case strings.Contains(upper, "RC4"):
		return "← broken since 2013, still lurking in configs like a cockroach."
	case strings.Contains(upper, "DES_CBC3") || strings.Contains(upper, "3DES"):
		return "← grandma's cipher. Sweet32 says hi."
	case strings.Contains(upper, "DES"):
		return "← 56-bit key. Crackable before your coffee gets cold."
	case strings.Contains(upper, "ANON") || strings.Contains(upper, "ADH") || strings.Contains(upper, "AECDH"):
		return "← anonymous key exchange = no authentication = no security."
	case strings.Contains(upper, "CBC"):
		return "← BEAST, Lucky13, and POODLE walk into a bar. This cipher was already there."
	default:
		return ""
	}
}

// tlsVersionSass returns a sarcastic annotation for deprecated TLS versions.
func tlsVersionSass(version string) string {
	switch version {
	case "TLS 1.0":
		return "← deprecated before TikTok existed"
	case "TLS 1.1":
		return "← nobody threw a funeral, but it's dead"
	case "SSL 3.0":
		return "← POODLE ate this alive in 2014"
	default:
		return ""
	}
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
		if !v.Supported {
			lines = append(lines, fmt.Sprintf("  %-10s %s", v.Version, Theme.MutedStyle.Render("not supported")))
			continue
		}
		icon := StatusIcon(v.Grade)
		sass := tlsVersionSass(v.Version)
		if sass != "" {
			lines = append(lines, fmt.Sprintf("  %-10s %s  %s", v.Version, icon, Theme.ErrorStyle.Render(sass)))
		} else {
			lines = append(lines, fmt.Sprintf("  %-10s %s", v.Version, icon))
		}
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
			sass := cipherSass(suite.Name)
			if sass != "" {
				lines = append(lines, fmt.Sprintf("    %s %s  %s",
					Theme.ErrorStyle.Render("x"),
					Theme.MutedStyle.Render(suite.Name),
					Theme.ErrorStyle.Render(sass)))
			} else {
				lines = append(lines, fmt.Sprintf("    %s %s",
					Theme.ErrorStyle.Render("x"),
					Theme.MutedStyle.Render(suite.Name)))
			}
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
