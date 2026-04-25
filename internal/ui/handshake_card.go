package ui

import (
	"fmt"
	"math/rand"

	"github.com/thexsa/peep/internal/analyzer"
)

// RenderHandshakeCard renders the TLS handshake summary.
func RenderHandshakeCard(hs analyzer.HandshakeAnalysis) string {
	header := Theme.BoldStyle.Render("TLS HANDSHAKE")

	var lines []string
	lines = append(lines, header)
	lines = append(lines, "")

	// TLS Version
	versionGrade := StatusIcon(hs.VersionGrade)
	lines = append(lines, renderKV("TLS Version", fmt.Sprintf("%s  %s", hs.TLSVersion, versionGrade)))
	comment := tlsVersionComment(hs.TLSVersion)
	if comment != "" {
		lines = append(lines, fmt.Sprintf("                   %s", Theme.MutedStyle.Render(comment)))
	}

	// Cipher Suite
	cipherGrade := StatusIcon(hs.CipherGrade)
	lines = append(lines, renderKV("Cipher Suite", fmt.Sprintf("%s  %s", hs.CipherSuite, cipherGrade)))

	return ApplyBorder(lines, SectionBorder) + "\n"
}

func tlsVersionComment(version string) string {
	switch version {
	case "TLSv1.3":
		pool := []string{
			"Finally, someone who keeps up with the times.",
			"The gold standard. This is the way.",
			"TLS 1.3 — fast, secure, and not from the stone age.",
		}
		return pool[rand.Intn(len(pool))]
	case "TLSv1.2":
		pool := []string{
			"Fine. Not exciting, but it'll do. Like plain oatmeal.",
			"Acceptable. Provided the cipher suite isn't garbage.",
			"TLS 1.2 — the Honda Civic of encryption. Reliable, boring.",
		}
		return pool[rand.Intn(len(pool))]
	case "TLSv1.1":
		pool := []string{
			"TLS 1.1?! What year is it? This was deprecated before TikTok existed.",
			"Deprecated since 2021. You're two protocol generations behind.",
			"TLS 1.1 — the Internet's equivalent of using a flip phone in 2026.",
		}
		return pool[rand.Intn(len(pool))]
	case "TLSv1.0":
		pool := []string{
			"TLS 1.0. NINETEEN NINETY NINE called and wants its protocol back.",
			"Screen door on a bank vault. Anyone can walk through it.",
			"This protocol has more holes than Swiss cheese at a shooting range.",
		}
		return pool[rand.Intn(len(pool))]
	default:
		return ""
	}
}
