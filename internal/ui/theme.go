package ui

import (
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"
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

// borderOverhead is the number of characters consumed by the border prefix.
// "┃  " = 1 (border char) + 2 (spaces) = 3 visible columns, but the
// ANSI color codes are invisible. We use 4 to be safe.
const borderOverhead = 4

// TermWidth returns the current terminal width, defaulting to 100 if
// detection fails.
func TermWidth() int {
	w, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || w <= 0 {
		return 100
	}
	return w
}

// ContentWidth returns the usable content width after accounting for
// the border prefix and a given indent (in spaces).
func ContentWidth(indent int) int {
	w := TermWidth() - borderOverhead - indent
	if w < 40 {
		return 40
	}
	return w
}

// ApplyBorder prepends a border prefix to each line and joins them.
func ApplyBorder(lines []string, prefix string) string {
	var bordered []string
	for _, line := range lines {
		bordered = append(bordered, prefix+line)
	}
	return strings.Join(bordered, "\n")
}

// WrapText word-wraps a string to fit within maxWidth characters.
// The first line has no indent. Continuation lines are prefixed with indent.
func WrapText(text string, indent string, maxWidth int) []string {
	if maxWidth <= 0 {
		maxWidth = 76
	}

	words := strings.Fields(text)
	if len(words) == 0 {
		return nil
	}

	var lines []string
	currentLine := words[0]

	for _, word := range words[1:] {
		if len(currentLine)+1+len(word) > maxWidth {
			lines = append(lines, currentLine)
			currentLine = word
		} else {
			currentLine += " " + word
		}
	}
	lines = append(lines, currentLine)

	return lines
}

// WrapAndStyle word-wraps text and applies a lipgloss style.
// Returns lines where the first line has no prefix and continuation
// lines are indented. Caller is responsible for prepending the indent
// to the first line.
func WrapAndStyle(text string, indent string, maxWidth int, style lipgloss.Style) []string {
	wrapped := WrapText(text, indent, maxWidth)
	var styled []string
	for i, line := range wrapped {
		if i > 0 {
			styled = append(styled, style.Render(indent+line))
		} else {
			styled = append(styled, style.Render(line))
		}
	}
	return styled
}

// wrapBlock word-wraps text and returns lines where ALL lines
// (including the first) are prefixed with the indent and styled.
func wrapBlock(text string, indent string, maxWidth int, style lipgloss.Style) []string {
	wrapped := WrapText(text, indent, maxWidth)
	var styled []string
	for i, line := range wrapped {
		if i > 0 {
			styled = append(styled, indent+style.Render(line))
		} else {
			styled = append(styled, indent+style.Render(line))
		}
	}
	return styled
}
