package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/thexsa/peep/internal/analyzer"
)

// RenderChainDiagram produces a visual chain-of-trust tree in the terminal.
func RenderChainDiagram(chain analyzer.ChainAnalysis, personality analyzer.Personality) string {
	if len(chain.Certificates) == 0 {
		return Theme.ErrorStyle.Render("No certificates found in chain!")
	}

	header := Theme.TitleStyle.Render("🔗 Chain of Trust")
	var lines []string
	lines = append(lines, header)
	lines = append(lines, "")

	// Render in reverse order (root at top, leaf at bottom)
	reversed := make([]analyzer.CertAnalysis, len(chain.Certificates))
	for i, cert := range chain.Certificates {
		reversed[len(chain.Certificates)-1-i] = cert
	}

	for i, cert := range reversed {
		isLast := i == len(reversed)-1
		lines = append(lines, renderChainNode(cert, i, isLast, len(reversed), personality)...)
	}

	// Chain-level notes
	if chain.HasUnnecessaryRoot {
		note := "\n" + Theme.WarningStyle.Render("⚠️  Server is sending the Root CA cert — this is unnecessary baggage.")
		if personality == analyzer.Rude {
			note += "\n" + Theme.MutedStyle.Render("   The root cert is already in the trust store, genius. Stop wasting bandwidth.")
		} else {
			note += "\n" + Theme.MutedStyle.Render("   The root cert should already be in the client's trust store. Sending it wastes bandwidth.")
		}
		lines = append(lines, note)
	}

	if chain.HasMissingIntermediate {
		note := "\n" + Theme.ErrorStyle.Render("❌ Missing intermediate certificate(s)!")
		if personality == analyzer.Rude {
			note += "\n" + Theme.MutedStyle.Render("   You literally forgot to include the cert that vouches for the leaf. How is this in production?")
		} else {
			note += "\n" + Theme.MutedStyle.Render("   The server didn't send all intermediate certs. Some clients will reject this connection.")
		}
		lines = append(lines, note)
	}

	if !chain.ChainOrderCorrect {
		note := "\n" + Theme.ErrorStyle.Render("❌ Chain order is wrong!")
		if personality == analyzer.Rude {
			note += "\n" + Theme.MutedStyle.Render("   The certs are in the wrong order. It's like reading a book from chapter 5 to chapter 1. Fix it.")
		} else {
			note += "\n" + Theme.MutedStyle.Render("   Certificates should be ordered: leaf → intermediate(s) → root. This chain is jumbled.")
		}
		lines = append(lines, note)
	}

	// Trust store verification
	if chain.TrustStoreVerified {
		lines = append(lines, "")
		lines = append(lines, Theme.SuccessStyle.Render("🔒 Chain verified against system trust store — all good!"))
	} else if chain.VerificationError != "" {
		lines = append(lines, "")
		lines = append(lines, Theme.ErrorStyle.Render(fmt.Sprintf("🔓 Trust store verification FAILED: %s", chain.VerificationError)))
	}

	content := lipgloss.JoinVertical(lipgloss.Left, lines...)
	return Theme.CardStyle.Render(content)
}

// renderChainNode renders a single node in the chain tree.
func renderChainNode(cert analyzer.CertAnalysis, index int, isLast bool, total int, personality analyzer.Personality) []string {
	var lines []string

	// Determine connector characters
	connector := "├── "
	prefix := "│   "
	if isLast {
		connector = "└── "
		prefix = "    "
	}
	if index == 0 && total > 1 {
		connector = ""
		prefix = "│   "
	}

	// Role icon and name
	roleIcon := getRoleIcon(cert.Role)
	name := cert.CommonName
	if name == "" {
		name = cert.Subject
	}
	if cert.IsWildcard {
		name += " (Wildcard)"
	}

	roleLine := fmt.Sprintf("%s%s %s", connector, roleIcon, Theme.BoldStyle.Render(name))
	lines = append(lines, roleLine)

	// Role explanation
	roleExpl := Theme.MutedStyle.Render(fmt.Sprintf("%sRole: %s", prefix, cert.Role.RoleExplanation()))
	lines = append(lines, roleExpl)

	// Status
	statusStr := StatusBadge(cert.OverallGrade)
	lines = append(lines, fmt.Sprintf("%sStatus: %s", prefix, statusStr))

	// Expiry
	expiryStr := formatExpiry(cert, personality)
	lines = append(lines, fmt.Sprintf("%sExpires: %s", prefix, expiryStr))

	// SANs for leaf cert
	if cert.Role == analyzer.RoleLeaf && len(cert.DNSNames) > 0 {
		sans := strings.Join(cert.DNSNames, ", ")
		if len(sans) > 80 {
			sans = sans[:77] + "..."
		}
		lines = append(lines, fmt.Sprintf("%sCovers: %s", prefix, Theme.InfoStyle.Render(sans)))
	}

	// Key info
	lines = append(lines, fmt.Sprintf("%sKey: %s", prefix, Theme.MutedStyle.Render(cert.KeyType)))

	// Self-signed warning
	if cert.IsSelfSigned && cert.Role == analyzer.RoleLeaf {
		warning := Theme.WarningStyle.Render("⚠️  Self-signed!")
		lines = append(lines, fmt.Sprintf("%s%s", prefix, warning))
	}

	// Hostname mismatch for leaf
	if cert.Role == analyzer.RoleLeaf && !cert.HostnameMatch {
		warning := Theme.ErrorStyle.Render("❌ Hostname does NOT match this cert!")
		lines = append(lines, fmt.Sprintf("%s%s", prefix, warning))
	}

	lines = append(lines, prefix)

	return lines
}

func getRoleIcon(role analyzer.CertRole) string {
	switch role {
	case analyzer.RoleLeaf:
		return "📄"
	case analyzer.RoleIntermediate:
		return "📋"
	case analyzer.RoleRoot:
		return "🏛️ "
	default:
		return "❓"
	}
}

func formatExpiry(cert analyzer.CertAnalysis, personality analyzer.Personality) string {
	if cert.IsExpired {
		if personality == analyzer.Rude {
			return Theme.ErrorStyle.Render(fmt.Sprintf("💀 EXPIRED %d days ago — are you even trying?", -cert.DaysRemaining))
		}
		return Theme.ErrorStyle.Render(fmt.Sprintf("💀 Expired %d days ago", -cert.DaysRemaining))
	}

	expiryDate := cert.NotAfter.Format("Jan 02, 2006")

	if cert.DaysRemaining > 365 {
		years := cert.DaysRemaining / 365
		comment := fmt.Sprintf("(you'll probably change jobs %d times before then)", years)
		if personality == analyzer.Rude {
			comment = "(at least SOMETHING here was done right)"
		}
		return Theme.SuccessStyle.Render(fmt.Sprintf("%d days (%s) %s", cert.DaysRemaining, expiryDate, comment))
	}

	if cert.DaysRemaining > 90 {
		return Theme.SuccessStyle.Render(fmt.Sprintf("%d days (%s)", cert.DaysRemaining, expiryDate))
	}

	if cert.DaysRemaining > 30 {
		comment := "— time to start planning renewal"
		if personality == analyzer.Rude {
			comment = "— tick tock, procrastinator"
		}
		return Theme.WarningStyle.Render(fmt.Sprintf("%d days (%s) %s", cert.DaysRemaining, expiryDate, comment))
	}

	comment := "— RENEW THIS NOW!"
	if personality == analyzer.Rude {
		comment = "— this is YOUR fault when it expires"
	}
	return Theme.ErrorStyle.Render(fmt.Sprintf("%d days (%s) %s", cert.DaysRemaining, expiryDate, comment))
}
