package ui

import (
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
	BgAccent   lipgloss.Color

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
	CardStyle      lipgloss.Style
	KeyStyle       lipgloss.Style
	ValueStyle     lipgloss.Style
}{
	Primary:  lipgloss.Color("#6366F1"),
	Success:  lipgloss.Color("#10B981"),
	Warning:  lipgloss.Color("#F59E0B"),
	Error:    lipgloss.Color("#F43F5E"),
	Info:     lipgloss.Color("#38BDF8"),
	Muted:    lipgloss.Color("#94A3B8"),
	BgAccent: lipgloss.Color("#1E293B"),

	TitleStyle: lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#6366F1")),

	SubtitleStyle: lipgloss.NewStyle().
		Foreground(lipgloss.Color("#94A3B8")),

	SuccessStyle: lipgloss.NewStyle().
		Foreground(lipgloss.Color("#10B981")),

	WarningStyle: lipgloss.NewStyle().
		Foreground(lipgloss.Color("#F59E0B")),

	ErrorStyle: lipgloss.NewStyle().
		Foreground(lipgloss.Color("#F43F5E")),

	InfoStyle: lipgloss.NewStyle().
		Foreground(lipgloss.Color("#38BDF8")),

	MutedStyle: lipgloss.NewStyle().
		Foreground(lipgloss.Color("#94A3B8")),

	BoldStyle: lipgloss.NewStyle().
		Bold(true),

	BoxStyle: lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#6366F1")).
		Padding(0, 1),

	HeaderBoxStyle: lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#6366F1")).
		Padding(0, 2).
		MarginBottom(1),

	CardStyle: lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#94A3B8")).
		Padding(0, 1).
		MarginBottom(1),

	KeyStyle: lipgloss.NewStyle().
		Foreground(lipgloss.Color("#38BDF8")).
		Bold(true).
		Width(16),

	ValueStyle: lipgloss.NewStyle().
		Foreground(lipgloss.Color("#E2E8F0")),
}
