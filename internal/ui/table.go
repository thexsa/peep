package ui

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
	"github.com/thexsa/peep/internal/analyzer"
)

// RenderWarnings renders all warnings with explanations.
func RenderWarnings(warnings []analyzer.Warning) string {
	if len(warnings) == 0 {
		return ""
	}

	header := Theme.BoldStyle.Render(fmt.Sprintf("FINDINGS (%d)", len(warnings)))

	var lines []string
	lines = append(lines, header)
	lines = append(lines, "")

	for _, w := range warnings {
		icon := StatusIcon(w.Severity)
		lines = append(lines, fmt.Sprintf("%s %s", icon, w.Title))
		lines = append(lines, fmt.Sprintf("     %s", Theme.MutedStyle.Render(w.Detail)))

		if w.Why != "" {
			lines = append(lines, fmt.Sprintf("     %s", Theme.InfoStyle.Render(w.Why)))
		}
		lines = append(lines, "")
	}

	content := lipgloss.JoinVertical(lipgloss.Left, lines...)
	return Theme.SectionStyle.Render(content) + "\n"
}
