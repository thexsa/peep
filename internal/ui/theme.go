package ui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Theme holds all the styled renderers for the peep UI.
var Theme = struct {
	// Brand colors
	Primary    lipgloss.Color
	Success    lipgloss.Color
	Warning    lipgloss.Color
	Error      lipgloss.Color
	Info       lipgloss.Color
	Muted      lipgloss.Color

	// Styled components
	TitleStyle     lipgloss.Style
	SubtitleStyle  lipgloss.Style
	SuccessStyle   lipgloss.Style
	WarningStyle   lipgloss.Style
	ErrorStyle     lipgloss.Style
	InfoStyle      lipgloss.Style
	MutedStyle     lipgloss.Style
	BoldStyle      lipgloss.Style
	BoxStyle       lipgloss.Style
	HeaderBoxStyle lipgloss.Style
	SectionStyle   lipgloss.Style
	CardStyle      lipgloss.Style
	KeyStyle       lipgloss.Style
	ValueStyle     lipgloss.Style
	DimKeyStyle    lipgloss.Style
}{
	Primary:  lipgloss.Color("#818CF8"),
	Success:  lipgloss.Color("#34D399"),
	Warning:  lipgloss.Color("#FBBF24"),
	Error:    lipgloss.Color("#FB7185"),
	Info:     lipgloss.Color("#7DD3FC"),
	Muted:    lipgloss.Color("#64748B"),

	TitleStyle: lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#E2E8F0")),

	SubtitleStyle: lipgloss.NewStyle().
		Foreground(lipgloss.Color("#94A3B8")),

	SuccessStyle: lipgloss.NewStyle().
		Foreground(lipgloss.Color("#34D399")),

	WarningStyle: lipgloss.NewStyle().
		Foreground(lipgloss.Color("#FBBF24")),

	ErrorStyle: lipgloss.NewStyle().
		Foreground(lipgloss.Color("#FB7185")),

	InfoStyle: lipgloss.NewStyle().
		Foreground(lipgloss.Color("#7DD3FC")),

	MutedStyle: lipgloss.NewStyle().
		Foreground(lipgloss.Color("#64748B")),

	BoldStyle: lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#E2E8F0")),

	BoxStyle: lipgloss.NewStyle().
		Padding(0, 1),

	HeaderBoxStyle: lipgloss.NewStyle().
		BorderLeft(true).
		BorderStyle(lipgloss.ThickBorder()).
		BorderForeground(lipgloss.Color("#818CF8")).
		PaddingLeft(2).
		MarginBottom(1),

	SectionStyle: lipgloss.NewStyle().
		BorderLeft(true).
		BorderStyle(lipgloss.ThickBorder()).
		BorderForeground(lipgloss.Color("#64748B")).
		PaddingLeft(2),

	CardStyle: lipgloss.NewStyle().
		BorderLeft(true).
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("#475569")).
		PaddingLeft(2),

	KeyStyle: lipgloss.NewStyle().
		Foreground(lipgloss.Color("#94A3B8")).
		Width(18),

	DimKeyStyle: lipgloss.NewStyle().
		Foreground(lipgloss.Color("#64748B")).
		Width(18),

	ValueStyle: lipgloss.NewStyle().
		Foreground(lipgloss.Color("#E2E8F0")),
}

// Manual border prefixes — avoids lipgloss right-padding that causes
// misalignment when terminal width is narrower than the longest line.
var (
	// CardBorder uses a thin border for cert cards
	CardBorder = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#475569")).
			Render("│") + "  "

	// SectionBorder uses a thick border for sections (chain, handshake, findings)
	SectionBorder = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#64748B")).
			Render("┃") + "  "

	// HeaderBorder uses a thick primary-colored border for the header
	HeaderBorder = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#818CF8")).
			Render("┃") + "  "
)

// ApplyBorder prepends a border prefix to each line and joins them.
func ApplyBorder(lines []string, prefix string) string {
	var bordered []string
	for _, line := range lines {
		bordered = append(bordered, prefix+line)
	}
	return strings.Join(bordered, "\n")
}
