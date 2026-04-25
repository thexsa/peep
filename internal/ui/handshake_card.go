package ui

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
	"github.com/thexsa/peep/internal/analyzer"
)

// RenderHandshakeCard renders the TLS handshake summary.
func RenderHandshakeCard(hs analyzer.HandshakeAnalysis, personality analyzer.Personality) string {
	header := Theme.TitleStyle.Render("🤝 TLS Handshake")

	var lines []string
	lines = append(lines, header)
	lines = append(lines, "")

	// TLS Version
	versionGrade := StatusBadge(hs.VersionGrade)
	versionComment := tlsVersionComment(hs.TLSVersion, personality)
	lines = append(lines, renderKV("TLS Version", fmt.Sprintf("%s  %s", hs.TLSVersion, versionGrade)))
	if versionComment != "" {
		lines = append(lines, fmt.Sprintf("                 %s", Theme.MutedStyle.Render(versionComment)))
	}

	// Cipher Suite
	cipherGrade := StatusBadge(hs.CipherGrade)
	lines = append(lines, renderKV("Cipher Suite", fmt.Sprintf("%s  %s", hs.CipherSuite, cipherGrade)))

	// Overall
	lines = append(lines, "")
	lines = append(lines, renderKV("Handshake", fmt.Sprintf("%s  %s", StatusBadge(hs.OverallGrade), StatusDescription(hs.OverallGrade, personality))))

	content := lipgloss.JoinVertical(lipgloss.Left, lines...)
	return Theme.CardStyle.Render(content)
}

func tlsVersionComment(version string, personality analyzer.Personality) string {
	switch version {
	case "TLSv1.3":
		if personality == analyzer.Rude {
			return "Finally, someone who keeps up with the times."
		}
		return "The gold standard. Fast and secure."
	case "TLSv1.2":
		if personality == analyzer.Rude {
			return "Fine. Not exciting, but it'll do. Like plain oatmeal."
		}
		return "Still solid with the right cipher suites."
	case "TLSv1.1":
		if personality == analyzer.Rude {
			return "TLS 1.1?! What year is it? This was deprecated before TikTok existed."
		}
		return "Deprecated since 2021. Time to upgrade."
	case "TLSv1.0":
		if personality == analyzer.Rude {
			return "TLS 1.0. NINETEEN NINETY NINE called and wants its protocol back."
		}
		return "Screen door on a bank vault. Anyone can get through it."
	default:
		return ""
	}
}
