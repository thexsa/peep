package ui

import (
	"fmt"

	"github.com/thexsa/peep/internal/analyzer"
)

// StatusBadge returns a styled status badge string.
func StatusBadge(status analyzer.HealthStatus) string {
	switch status {
	case analyzer.ClearSkies:
		return Theme.SuccessStyle.Render("✅ Clear Skies")
	case analyzer.Cloudy:
		return Theme.WarningStyle.Render("⚠️  Cloudy")
	case analyzer.Stormy:
		return Theme.ErrorStyle.Render("❌ Stormy")
	default:
		return Theme.MutedStyle.Render("❓ Unknown")
	}
}

// StatusDescription returns a one-liner for the status.
func StatusDescription(status analyzer.HealthStatus, personality analyzer.Personality) string {
	switch status {
	case analyzer.ClearSkies:
		if personality == analyzer.Rude {
			return "Congrats, you didn't screw this one up. Everything's fine."
		}
		return "Everything's looking good. Go grab a coffee. ☕"
	case analyzer.Cloudy:
		if personality == analyzer.Rude {
			return "It works, but barely. Like your New Year's resolutions."
		}
		return "Not broken, but not great. Like milk that's one day from expiring. 🥛"
	case analyzer.Stormy:
		if personality == analyzer.Rude {
			return "This is a dumpster fire. Whoever set this up should update their resume."
		}
		return "Houston, we have a problem. This needs immediate attention. 🚨"
	default:
		return ""
	}
}

// RenderOverallStatus renders the overall scan status with description.
func RenderOverallStatus(status analyzer.HealthStatus, personality analyzer.Personality) string {
	badge := StatusBadge(status)
	desc := StatusDescription(status, personality)

	header := Theme.BoldStyle.Render("Overall Assessment")
	content := fmt.Sprintf("%s\n%s\n%s", header, badge, Theme.MutedStyle.Render(desc))
	return Theme.BoxStyle.Render(content)
}
