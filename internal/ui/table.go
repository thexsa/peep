package ui

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
	"github.com/thexsa/peep/internal/analyzer"
)

// RenderWarnings renders all warnings with optional --why explanations.
func RenderWarnings(warnings []analyzer.Warning, showWhy bool, personality analyzer.Personality) string {
	if len(warnings) == 0 {
		return ""
	}

	header := Theme.TitleStyle.Render(fmt.Sprintf("📋 Findings (%d)", len(warnings)))

	var lines []string
	lines = append(lines, header)
	lines = append(lines, "")

	for _, w := range warnings {
		icon := "⚠️ "
		style := Theme.WarningStyle
		if w.Severity == analyzer.Stormy {
			icon = "❌"
			style = Theme.ErrorStyle
		}

		lines = append(lines, style.Render(fmt.Sprintf("%s %s", icon, w.Title)))
		lines = append(lines, fmt.Sprintf("   %s", Theme.MutedStyle.Render(w.Detail)))

		if showWhy {
			why := w.Why(personality)
			if why != "" {
				lines = append(lines, fmt.Sprintf("   💡 %s", Theme.InfoStyle.Render(why)))
			}
		}
		lines = append(lines, "")
	}

	content := lipgloss.JoinVertical(lipgloss.Left, lines...)
	return Theme.CardStyle.Render(content)
}
