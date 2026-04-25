package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/thexsa/peep/internal/analyzer"
)

// RenderCertCard renders a detailed certificate info card.
func RenderCertCard(cert analyzer.CertAnalysis) string {
	name := cert.CommonName
	if name == "" {
		name = cert.Subject
	}

	// Header line
	header := Theme.BoldStyle.Render(fmt.Sprintf("%s  %s", cert.Role, name))

	var kvLines []string

	kvLines = append(kvLines, renderKV("Subject", cert.Subject))
	kvLines = append(kvLines, renderKV("Issuer", cert.Issuer))

	if cert.Organization != "" {
		kvLines = append(kvLines, renderKV("Organization", cert.Organization))
	}

	// Role explanation
	kvLines = append(kvLines, renderKV("Role", Theme.MutedStyle.Render(cert.Role.RoleExplanation())))

	// Status
	kvLines = append(kvLines, renderKV("Status", StatusBadge(cert.OverallGrade)))

	// SANs
	if len(cert.DNSNames) > 0 {
		sans := strings.Join(cert.DNSNames, ", ")
		if len(sans) > 80 {
			sans = sans[:77] + "..."
		}
		kvLines = append(kvLines, renderKV("DNS Names", sans))
	}
	if len(cert.IPAddresses) > 0 {
		kvLines = append(kvLines, renderKV("IP SANs", strings.Join(cert.IPAddresses, ", ")))
	}

	// Hostname match for leaf
	if cert.Role == analyzer.RoleLeaf {
		if cert.HostnameMatch {
			kvLines = append(kvLines, renderKV("Host Match", Theme.SuccessStyle.Render("Yes")))
		} else {
			kvLines = append(kvLines, renderKV("Host Match", Theme.ErrorStyle.Render("NO — wrong cert installed")))
		}
	}

	// Dates
	kvLines = append(kvLines, renderKV("Not Before", cert.NotBefore.Format("Jan 02, 2006 15:04:05 MST")))
	kvLines = append(kvLines, renderKV("Not After", cert.NotAfter.Format("Jan 02, 2006 15:04:05 MST")))
	kvLines = append(kvLines, renderKV("Days Left", formatExpiry(cert)))

	// Key info
	keyInfo := cert.KeyType
	if cert.KeyBits > 0 {
		keyInfo = fmt.Sprintf("%s (%d bits)", cert.KeyType, cert.KeyBits)
	}
	kvLines = append(kvLines, renderKV("Key", fmt.Sprintf("%s  %s", keyInfo, StatusIcon(cert.KeyGrade))))

	// Signature
	kvLines = append(kvLines, renderKV("Signature", fmt.Sprintf("%s  %s", cert.SignatureAlg, StatusIcon(cert.SignatureGrade))))

	// Serial
	kvLines = append(kvLines, renderKV("Serial", Theme.MutedStyle.Render(cert.SerialNumber)))

	// Fingerprint
	fp := cert.Fingerprint
	if len(fp) > 40 {
		fp = formatFingerprint(fp)
	}
	kvLines = append(kvLines, renderKV("SHA-256", Theme.MutedStyle.Render(fp)))

	// Flags
	var flags []string
	if cert.IsWildcard {
		flags = append(flags, "Wildcard")
	}
	if cert.IsSelfSigned {
		flags = append(flags, "Self-signed")
	}
	if cert.IsCA {
		flags = append(flags, "CA")
	}
	if len(flags) > 0 {
		kvLines = append(kvLines, renderKV("Flags", strings.Join(flags, ", ")))
	}

	content := lipgloss.JoinVertical(lipgloss.Left, append([]string{header}, kvLines...)...)
	return Theme.CardStyle.Render(content)
}

func renderKV(key, value string) string {
	return fmt.Sprintf("%s %s", Theme.KeyStyle.Render(key+":"), value)
}

func formatFingerprint(fp string) string {
	var parts []string
	for i := 0; i < len(fp); i += 4 {
		end := i + 4
		if end > len(fp) {
			end = len(fp)
		}
		parts = append(parts, fp[i:end])
	}
	return strings.Join(parts, ":")
}

func formatExpiry(cert analyzer.CertAnalysis) string {
	if cert.IsExpired {
		return Theme.ErrorStyle.Render(fmt.Sprintf("EXPIRED %d days ago — %s", -cert.DaysRemaining, RandomExpiredComment()))
	}

	expiryDate := cert.NotAfter.Format("Jan 02, 2006")
	comment := RandomExpiryComment(cert.DaysRemaining)

	if cert.DaysRemaining > 30 {
		return Theme.SuccessStyle.Render(fmt.Sprintf("%d days (%s)", cert.DaysRemaining, expiryDate)) +
			Theme.MutedStyle.Render(fmt.Sprintf(" — %s", comment))
	}
	if cert.DaysRemaining > 14 {
		return Theme.WarningStyle.Render(fmt.Sprintf("%d days (%s)", cert.DaysRemaining, expiryDate)) +
			Theme.MutedStyle.Render(fmt.Sprintf(" — %s", comment))
	}
	return Theme.ErrorStyle.Render(fmt.Sprintf("%d days (%s)", cert.DaysRemaining, expiryDate)) +
		Theme.MutedStyle.Render(fmt.Sprintf(" — %s", comment))
}
