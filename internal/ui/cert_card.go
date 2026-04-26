package ui

import (
	"fmt"
	"strings"

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

	var lines []string
	lines = append(lines, header)

	lines = append(lines, renderKV("Subject", cert.Subject))
	lines = append(lines, renderKV("Issuer", cert.Issuer))

	if cert.Organization != "" {
		lines = append(lines, renderKV("Organization", cert.Organization))
	}

	// Role explanation
	roleExpl := cert.Role.RoleExplanation()
	kvIndent := "                    " // 20 chars to align with value column
	roleW := ContentWidth(20)          // 18 (key width) + 2 (spacing)
	roleLines := WrapText(roleExpl, kvIndent, roleW)
	for i, rl := range roleLines {
		if i == 0 {
			lines = append(lines, renderKV("Role", Theme.MutedStyle.Render(rl)))
		} else {
			lines = append(lines, kvIndent+Theme.MutedStyle.Render(rl))
		}
	}

	// Status
	lines = append(lines, renderKV("Status", StatusBadge(cert.OverallGrade)))

	// SANs
	if len(cert.DNSNames) > 0 {
		sans := strings.Join(cert.DNSNames, ", ")
		sanW := ContentWidth(20)
		sanLines := WrapText(sans, kvIndent, sanW)
		for i, sl := range sanLines {
			if i == 0 {
				lines = append(lines, renderKV("DNS Names", sl))
			} else {
				lines = append(lines, kvIndent+sl)
			}
		}
	}
	if len(cert.IPAddresses) > 0 {
		lines = append(lines, renderKV("IP SANs", strings.Join(cert.IPAddresses, ", ")))
	}

	// Hostname match for leaf
	if cert.Role == analyzer.RoleLeaf {
		if cert.HostnameMatch {
			lines = append(lines, renderKV("Host Match", Theme.SuccessStyle.Render("Yes")))
		} else {
			lines = append(lines, renderKV("Host Match", Theme.ErrorStyle.Render("NO — wrong cert installed")))
		}
	}

	// Dates
	lines = append(lines, renderKV("Not Before", cert.NotBefore.Format("Jan 02, 2006 15:04:05 MST")))
	lines = append(lines, renderKV("Not After", cert.NotAfter.Format("Jan 02, 2006 15:04:05 MST")))
	lines = append(lines, renderKV("Days Left", formatExpiry(cert)))

	// Key info
	keyInfo := cert.KeyType
	if cert.KeyBits > 0 {
		keyInfo = fmt.Sprintf("%s (%d bits)", cert.KeyType, cert.KeyBits)
	}
	lines = append(lines, renderKV("Key", fmt.Sprintf("%s  %s", keyInfo, StatusIcon(cert.KeyGrade))))

	// Signature
	lines = append(lines, renderKV("Signature", fmt.Sprintf("%s  %s", cert.SignatureAlg, StatusIcon(cert.SignatureGrade))))

	// Serial
	lines = append(lines, renderKV("Serial", Theme.MutedStyle.Render(cert.SerialNumber)))

	// Fingerprint
	fp := cert.Fingerprint
	if len(fp) > 40 {
		fp = formatFingerprint(fp)
	}
	lines = append(lines, renderKV("SHA-256", Theme.MutedStyle.Render(fp)))

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
		lines = append(lines, renderKV("Flags", strings.Join(flags, ", ")))
	}

	return ApplyBorder(lines, CardBorder)
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
