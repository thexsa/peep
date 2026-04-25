package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/thexsa/peep/internal/analyzer"
)

// RenderCertCard renders a detailed certificate info card.
func RenderCertCard(cert analyzer.CertAnalysis, personality analyzer.Personality) string {
	roleIcon := getRoleIcon(cert.Role)
	name := cert.CommonName
	if name == "" {
		name = cert.Subject
	}

	// Header
	header := Theme.TitleStyle.Render(fmt.Sprintf("%s %s — %s", roleIcon, cert.Role, name))

	// Build key-value lines
	var kvLines []string

	kvLines = append(kvLines, renderKV("Subject", cert.Subject))
	kvLines = append(kvLines, renderKV("Issuer", cert.Issuer))

	if cert.Organization != "" {
		kvLines = append(kvLines, renderKV("Organization", cert.Organization))
	}

	// Role explanation
	kvLines = append(kvLines, renderKV("Role", cert.Role.RoleExplanation()))

	// Status
	kvLines = append(kvLines, renderKV("Status", StatusBadge(cert.OverallGrade)+" "+StatusDescription(cert.OverallGrade, personality)))

	// SANs
	if len(cert.DNSNames) > 0 {
		kvLines = append(kvLines, renderKV("DNS Names", strings.Join(cert.DNSNames, ", ")))
	}
	if len(cert.IPAddresses) > 0 {
		kvLines = append(kvLines, renderKV("IP SANs", strings.Join(cert.IPAddresses, ", ")))
	}

	// Hostname match for leaf
	if cert.Role == analyzer.RoleLeaf {
		if cert.HostnameMatch {
			kvLines = append(kvLines, renderKV("Host Match", Theme.SuccessStyle.Render("✅ Yes — cert covers the target hostname")))
		} else {
			msg := "❌ No — this cert does NOT cover the hostname you connected to!"
			if personality == analyzer.Rude {
				msg = "❌ No — wrong cert! Did someone install the cert for a different domain? Classic."
			}
			kvLines = append(kvLines, renderKV("Host Match", Theme.ErrorStyle.Render(msg)))
		}
	}

	// Dates
	kvLines = append(kvLines, renderKV("Not Before", cert.NotBefore.Format("Jan 02, 2006 15:04:05 MST")))
	kvLines = append(kvLines, renderKV("Not After", cert.NotAfter.Format("Jan 02, 2006 15:04:05 MST")))
	kvLines = append(kvLines, renderKV("Days Left", formatExpiry(cert, personality)))

	// Key info
	keyInfo := cert.KeyType
	if cert.KeyBits > 0 {
		keyInfo = fmt.Sprintf("%s (%d bits)", cert.KeyType, cert.KeyBits)
	}
	keyGrade := StatusBadge(cert.KeyGrade)
	kvLines = append(kvLines, renderKV("Key", fmt.Sprintf("%s  %s", keyInfo, keyGrade)))

	// Signature
	sigGrade := StatusBadge(cert.SignatureGrade)
	kvLines = append(kvLines, renderKV("Signature", fmt.Sprintf("%s  %s", cert.SignatureAlg, sigGrade)))

	// Serial
	kvLines = append(kvLines, renderKV("Serial", cert.SerialNumber))

	// Fingerprint (abbreviated for readability)
	fp := cert.Fingerprint
	if len(fp) > 40 {
		fp = formatFingerprint(fp)
	}
	kvLines = append(kvLines, renderKV("SHA-256", Theme.MutedStyle.Render(fp)))

	// Flags
	var flags []string
	if cert.IsWildcard {
		flags = append(flags, "🃏 Wildcard")
	}
	if cert.IsSelfSigned {
		flags = append(flags, "🔄 Self-signed")
	}
	if cert.IsCA {
		flags = append(flags, "🏢 CA")
	}
	if len(flags) > 0 {
		kvLines = append(kvLines, renderKV("Flags", strings.Join(flags, "  ")))
	}

	content := lipgloss.JoinVertical(lipgloss.Left, append([]string{header, ""}, kvLines...)...)
	return Theme.CardStyle.Render(content)
}

func renderKV(key, value string) string {
	return fmt.Sprintf("%s %s", Theme.KeyStyle.Render(key+":"), value)
}

func formatFingerprint(fp string) string {
	// Format as colon-separated groups of 4 chars
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
