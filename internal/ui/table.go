package ui

import (
	"fmt"

	"github.com/thexsa/peep/internal/analyzer"
)

// RenderWarnings renders all warnings with explanations.
// When explain is true, adds detailed explanation, fix, and doc reference.
func RenderWarnings(warnings []analyzer.Warning, explain bool) string {
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

		if explain {
			if w.Explain != "" {
				lines = append(lines, "")
				lines = append(lines, fmt.Sprintf("     %s", Theme.BoldStyle.Render("Why this matters:")))
				lines = append(lines, fmt.Sprintf("     %s", Theme.MutedStyle.Render(w.Explain)))
			}
			if w.Fix != "" {
				lines = append(lines, "")
				lines = append(lines, fmt.Sprintf("     %s", Theme.BoldStyle.Render("Recommended fix:")))
				lines = append(lines, fmt.Sprintf("     %s", Theme.SuccessStyle.Render(w.Fix)))
			}
			if w.DocRef != "" {
				lines = append(lines, "")
				lines = append(lines, fmt.Sprintf("     %s  %s",
					Theme.MutedStyle.Render("📖 Learn more:"),
					Theme.InfoStyle.Render(w.DocRef)))
			}
		}
		lines = append(lines, "")
	}

	return ApplyBorder(lines, SectionBorder) + "\n"
}
