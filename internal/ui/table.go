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
	// 5 = indent for "     " prefix inside findings
	maxW := ContentWidth(5)
	indent := "     "

	var lines []string
	lines = append(lines, header)
	lines = append(lines, "")

	for _, w := range warnings {
		icon := StatusIcon(w.Severity)
		lines = append(lines, fmt.Sprintf("%s %s", icon, w.Title))

		// Detail — word wrapped
		lines = append(lines, wrapBlock(w.Detail, indent, maxW, Theme.MutedStyle)...)

		// Sarcastic comment — word wrapped
		if w.Why != "" {
			lines = append(lines, wrapBlock(w.Why, indent, maxW, Theme.InfoStyle)...)
		}

		if explain {
			if w.Explain != "" {
				lines = append(lines, "")
				lines = append(lines, fmt.Sprintf("%s%s", indent, Theme.BoldStyle.Render("Why this matters:")))
				lines = append(lines, wrapBlock(w.Explain, indent, maxW, Theme.MutedStyle)...)
			}
			if w.Fix != "" {
				lines = append(lines, "")
				lines = append(lines, fmt.Sprintf("%s%s", indent, Theme.BoldStyle.Render("Recommended fix:")))
				lines = append(lines, wrapBlock(w.Fix, indent, maxW, Theme.SuccessStyle)...)
			}
			if w.DocRef != "" {
				lines = append(lines, "")
				lines = append(lines, fmt.Sprintf("%s%s  %s", indent,
					Theme.MutedStyle.Render("📖 Learn more:"),
					Theme.InfoStyle.Render(w.DocRef)))
			}
		}
		lines = append(lines, "")
	}

	return ApplyBorder(lines, SectionBorder) + "\n"
}
