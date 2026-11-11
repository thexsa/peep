package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/thexsa/peep/internal/ui"
	"github.com/thexsa/peep/internal/updater"
)

var (
	flagUpdateCheck    bool
	flagUpdateForce    bool
	updateJustFinished bool // suppresses stale update notification after successful update
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update peep to the latest version",
	Long: `Check for and install the latest version of peep.

Automatically detects your install method:
  - Homebrew: runs brew upgrade thexsa/tap/peep
  - GitHub binary: downloads the latest release and replaces in-place
  - Dev build: tells you to git pull && make build

Examples:
  peep update              Update to latest
  peep update --check      Just check, don't install`,
	Aliases: []string{"upgrade"},
	RunE:    runUpdate,
}

func init() {
	updateCmd.Flags().BoolVar(&flagUpdateCheck, "check", false, "Just check for updates, don't install")
	updateCmd.Flags().BoolVar(&flagUpdateForce, "force", false, "Force update even if already on latest")
	rootCmd.AddCommand(updateCmd)
}

func printUpdateLine(s string) {
	fmt.Println(ui.StripEmoji(s))
}

func isPermissionError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrPermission) || os.IsPermission(err) {
		return true
	}
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "permission denied") || strings.Contains(lower, "access is denied")
}

func runUpdate(cmd *cobra.Command, args []string) error {
	if showExamples(cmd.Name()) {
		return nil
	}

	if flagPlainText {
		ui.EnablePlainText()
	}

	fmt.Println()
	printUpdateLine(ui.Theme.BoldStyle.Render("  Checking for updates..."))
	fmt.Println()

	info, err := updater.CheckForUpdate(Version)
	if err != nil {
		printUpdateLine(ui.Theme.ErrorStyle.Render(fmt.Sprintf("  [FAIL] Could not check for updates: %s", err)))
		return nil
	}

	// Save the check result to cache
	updater.SaveCheckResult(info.LatestVersion)

	method := info.InstallMethod

	printUpdateLine(ui.Theme.MutedStyle.Render(fmt.Sprintf("  Current version:  %s", versionDisplay(info.CurrentVersion))))
	printUpdateLine(ui.Theme.MutedStyle.Render(fmt.Sprintf("  Latest version:   %s", versionDisplay(info.LatestVersion))))
	printUpdateLine(ui.Theme.MutedStyle.Render(fmt.Sprintf("  Install method:   %s", method)))
	fmt.Println()

	if !info.UpdateAvailable && !flagUpdateForce {
		printUpdateLine(ui.Theme.SuccessStyle.Render(
			fmt.Sprintf("  You're already on the latest version (%s). Nothing to do.", versionDisplay(info.CurrentVersion)),
		))
		printUpdateLine(ui.Theme.MutedStyle.Render("  Your TLS game remains strong. 💪"))
		fmt.Println()
		return nil
	}

	if flagUpdateCheck {
		// Just report, don't install
		if info.UpdateAvailable {
			fmt.Print(ui.RenderUpdateNotification(info.CurrentVersion, info.LatestVersion))
		}
		return nil
	}

	if method == updater.InstallDevBuild {
		printUpdateLine(ui.Theme.WarningStyle.Render("  Dev build detected — can't self-update."))
		printUpdateLine(ui.Theme.MutedStyle.Render("  Update from source: git pull && make build"))
		fmt.Println()
		return nil
	}

	// Perform the update
	info.Force = flagUpdateForce
	updateVerb := "Downloading"
	if method == updater.InstallHomebrew {
		if flagUpdateForce {
			updateVerb = "Running brew reinstall"
		} else {
			updateVerb = "Running brew upgrade"
		}
	}
	printUpdateLine(ui.Theme.MutedStyle.Render(fmt.Sprintf("  %s...", updateVerb)))
	fmt.Println()

	if err := updater.PerformUpdate(info); err != nil {
		printUpdateLine(ui.Theme.ErrorStyle.Render(fmt.Sprintf("  [FAIL] Update failed: %s", err)))
		if isPermissionError(err) {
			if runtime.GOOS == "windows" {
				printUpdateLine(ui.Theme.WarningStyle.Render("  Tip: Open PowerShell or Command Prompt as Administrator, then run: peep update"))
			} else {
				printUpdateLine(ui.Theme.WarningStyle.Render("  Tip: Permission denied in install directory — try: sudo peep update"))
			}
		}
		fmt.Println()
		if method == updater.InstallGitHubBinary {
			printUpdateLine(ui.Theme.MutedStyle.Render("  You can update manually by downloading from:"))
			printUpdateLine(ui.Theme.MutedStyle.Render(fmt.Sprintf("  %s", info.ReleaseURL)))
		}
		fmt.Println()
		return nil
	}

	printUpdateLine(ui.Theme.SuccessStyle.Render(
		fmt.Sprintf("  Updated peep to %s! 🎉", versionDisplay(info.LatestVersion)),
	))
	fmt.Println()

	// Suppress the stale "Update available" notification from the background check
	updateJustFinished = true

	// Exec the NEW binary (resolved before rename/unlink so Windows doesn't run
	// peep.exe.old and Linux doesn't fail on "/proc/self/exe (deleted)") to show
	// its own What's New blurb.
	binPath := info.InstalledPath
	if binPath == "" {
		if exe, exeErr := os.Executable(); exeErr == nil {
			binPath = exe
		}
	}
	if binPath != "" {
		wnArgs := []string{"whatsnew", info.LatestVersion}
		if flagPlainText {
			wnArgs = append(wnArgs, "--plain-text")
		}
		whatsNew := exec.Command(binPath, wnArgs...)
		whatsNew.Stdout = os.Stdout
		whatsNew.Stderr = os.Stderr
		_ = whatsNew.Run() // best-effort, don't fail the update if this errors
	}

	return nil
}

// versionDisplay formats a version string for display,
// prefixing with "v" unless it's "dev" or already prefixed.
func versionDisplay(v string) string {
	if v == "dev" || v == "" || v[0] == 'v' {
		return v
	}
	return "v" + v
}
