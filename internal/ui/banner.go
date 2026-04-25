package ui

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
)

// RenderBanner displays the opening peep banner for a scan.
func RenderBanner(host, port, ip, protocol string) string {
	title := Theme.TitleStyle.Render("👀 peep — your digital eyes for TLS")
	lines := []string{
		title,
		Theme.InfoStyle.Render(fmt.Sprintf("   Peeping at: %s:%s", host, port)),
		Theme.MutedStyle.Render(fmt.Sprintf("   IP: %s", ip)),
		Theme.MutedStyle.Render(fmt.Sprintf("   Protocol: %s", protocol)),
	}

	content := lipgloss.JoinVertical(lipgloss.Left, lines...)
	return Theme.HeaderBoxStyle.Render(content)
}

// RenderVersion displays the version banner.
func RenderVersion(version string) string {
	logo := Theme.TitleStyle.Render(fmt.Sprintf("peep %s (•_•) 👀", version))
	tagline := Theme.MutedStyle.Render("Your digital eyes for TLS diagnostics.")
	built := Theme.MutedStyle.Render("Built with ❤️  and pure Go — no OpenSSL required.")

	content := lipgloss.JoinVertical(lipgloss.Left, logo, tagline, built)
	return Theme.HeaderBoxStyle.Render(content)
}
