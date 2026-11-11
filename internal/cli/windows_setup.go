package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/thexsa/peep/internal/ui"
	"github.com/thexsa/peep/internal/updater"
)

// windowsInstallPromptShown prevents showing the Windows setup prompt twice
// within the same CLI invocation (for example, inside `peep update` and again
// at the end of `Execute()`).
var windowsInstallPromptShown bool

type plainTextSafeWriter struct {
	w io.Writer
}

func (p plainTextSafeWriter) Write(b []byte) (int, error) {
	if ui.PlainTextMode {
		cleaned := ui.StripEmoji(string(b))
		if _, err := io.WriteString(p.w, cleaned); err != nil {
			return 0, err
		}
		return len(b), nil
	}
	return p.w.Write(b)
}

func displayExeParts(execPath string) (exeName, exeDir string) {
	trimmed := strings.Trim(strings.TrimSpace(execPath), `"`)
	trimmed = strings.TrimRight(trimmed, `\/`)
	lastSlash := strings.LastIndexAny(trimmed, `\/`)
	if lastSlash == -1 {
		return trimmed, "."
	}
	return trimmed[lastSlash+1:], trimmed[:lastSlash]
}

func sameFilePathLoose(a, b string) bool {
	na := strings.ReplaceAll(strings.Trim(strings.TrimSpace(a), `"`), `\`, `/`)
	nb := strings.ReplaceAll(strings.Trim(strings.TrimSpace(b), `"`), `\`, `/`)
	return na != "" && strings.EqualFold(na, nb)
}

// renderWindowsSetupExplanation builds the bordered explanation card describing
// what the non-admin Windows install script does.
func renderWindowsSetupExplanation(execPath, installDir string, fromUpdate bool) string {
	var lines []string

	title := "Windows Quick Setup (No Admin Required)"
	if fromUpdate {
		title = "Windows PATH Setup Available (No Admin Required)"
	}
	lines = append(lines, ui.Theme.BoldStyle.Render("  "+title))
	lines = append(lines, "")

	if strings.TrimSpace(execPath) != "" {
		exeName, exeDir := displayExeParts(execPath)
		lines = append(lines, ui.Theme.MutedStyle.Render(
			fmt.Sprintf("  You're currently running '%s' from:", exeName),
		))
		lines = append(lines, ui.Theme.InfoStyle.Render("    "+exeDir))
		lines = append(lines, "")
	}

	lines = append(lines, ui.Theme.ValueStyle.Render(
		"  peep can run its Windows install script (install.ps1) for your user account:",
	))
	lines = append(lines, ui.Theme.MutedStyle.Render(
		fmt.Sprintf("    * Installs peep.exe to %s", installDir),
	))
	lines = append(lines, ui.Theme.MutedStyle.Render(
		"    * Adds that folder to your Windows user PATH (no Administrator rights needed)",
	))
	lines = append(lines, ui.Theme.MutedStyle.Render(
		"    * Verifies the SHA-256 checksum and unblocks Windows SmartScreen",
	))
	lines = append(lines, ui.Theme.MutedStyle.Render(
		"    * Lets you simply run 'peep <endpoint>' from any directory",
	))

	return "\n" + ui.StripEmoji(ui.ApplyBorder(lines, ui.SectionBorder)) + "\n"
}

// promptYesNoDefaultYes reads a single line from in and returns:
//   - (true, true)   when the user accepted ("", "y", "yes")
//   - (false, true)  when the user explicitly declined ("n", "no", or other text)
//   - (false, false) on EOF / read failure without input (do not persist dismissal)
func promptYesNoDefaultYes(in io.Reader, out io.Writer, prompt string) (accepted bool, answered bool) {
	fmt.Fprint(out, ui.StripEmoji(prompt))
	reader := bufio.NewReader(in)
	line, err := reader.ReadString('\n')
	if err != nil && line == "" {
		fmt.Fprintln(out)
		return false, false
	}

	ans := strings.ToLower(strings.TrimSpace(line))
	switch ans {
	case "", "y", "yes":
		return true, true
	default:
		return false, true
	}
}

// offerWindowsInstallSetup prompts the Windows user (or runs immediately when
// autoConfirm is true) to execute the user-scope Windows installer.
func offerWindowsInstallSetup(targetVersion, sourceExecPath string, allowReuseSourceExe, fromUpdate, autoConfirm bool) {
	execPath := strings.TrimSpace(sourceExecPath)
	if execPath == "" {
		execPath = updater.CurrentExecutablePath()
	}
	offerWindowsInstallSetupIO(
		os.Stdin,
		os.Stdout,
		execPath,
		updater.DefaultWindowsInstallDir(),
		targetVersion,
		allowReuseSourceExe,
		fromUpdate,
		autoConfirm,
		updater.RunWindowsInstall,
		updater.DismissWindowsInstallPrompt,
	)
}

func offerWindowsInstallSetupIO(
	in io.Reader,
	out io.Writer,
	execPath string,
	installDir string,
	targetVersion string,
	allowReuseSourceExe bool,
	fromUpdate bool,
	autoConfirm bool,
	runInstall func(targetVersion, sourceExecPath string, allowReuseSourceExe bool, out io.Writer) (string, error),
	dismissFirstRun func() error,
) {
	windowsInstallPromptShown = true

	if !autoConfirm {
		fmt.Fprint(out, renderWindowsSetupExplanation(execPath, installDir, fromUpdate))
		fmt.Fprintln(out)
		prompt := ui.Theme.BoldStyle.Render("  Run the Windows install script now? [Y/n]: ")
		accepted, answered := promptYesNoDefaultYes(in, out, prompt)
		if !accepted {
			if answered && !fromUpdate && dismissFirstRun != nil {
				_ = dismissFirstRun()
			}
			fmt.Fprintln(out)
			fmt.Fprintln(out, ui.StripEmoji(ui.Theme.MutedStyle.Render(
				"  Skipped. You can run this setup anytime later with: peep update --install",
			)))
			fmt.Fprintln(out)
			return
		}
		fmt.Fprintln(out)
	} else {
		fmt.Fprintln(out, ui.StripEmoji(ui.Theme.BoldStyle.Render(
			"  Running Windows user-scope setup (no Administrator rights required)...",
		)))
		fmt.Fprintln(out)
	}

	installedDir, err := runInstall(targetVersion, execPath, allowReuseSourceExe, plainTextSafeWriter{w: out})
	if err != nil {
		fmt.Fprintln(out)
		fmt.Fprintln(out, ui.StripEmoji(ui.Theme.ErrorStyle.Render(
			fmt.Sprintf("  [FAIL] Windows setup failed: %s", err),
		)))
		fmt.Fprintln(out, ui.StripEmoji(ui.Theme.MutedStyle.Render(
			"  You can also run it directly in PowerShell:",
		)))
		fmt.Fprintln(out, ui.StripEmoji(ui.Theme.InfoStyle.Render(
			"    irm https://raw.githubusercontent.com/thexsa/peep/main/install.ps1 | iex",
		)))
		fmt.Fprintln(out)
		return
	}

	fmt.Fprintln(out)
	fmt.Fprintln(out, ui.StripEmoji(ui.Theme.SuccessStyle.Render(
		"  [OK] Windows user setup complete!",
	)))
	fmt.Fprintln(out, ui.StripEmoji(ui.Theme.MutedStyle.Render(
		"  Open a new PowerShell or Command Prompt window (or tab) and run:",
	)))
	fmt.Fprintln(out, ui.StripEmoji(ui.Theme.InfoStyle.Render(
		"    peep example.com",
	)))

	installedExe := filepath.Join(installedDir, "peep.exe")
	if strings.TrimSpace(execPath) != "" && !sameFilePathLoose(execPath, installedExe) {
		fmt.Fprintln(out, ui.StripEmoji(ui.Theme.MutedStyle.Render(
			fmt.Sprintf("  Tip: Once in a new terminal, you no longer need %s", execPath),
		)))
	}
	fmt.Fprintln(out)
}

// maybeOfferFirstRunWindowsInstall checks on Windows after normal CLI execution
// (e.g., on the first run after updating from v0.7.0 or older) whether peep has
// been set up on the user's PATH yet, and offers to run install.ps1 once.
func maybeOfferFirstRunWindowsInstall() {
	if windowsInstallPromptShown || flagJSON {
		return
	}
	if !updater.ShouldOfferFirstRunWindowsInstall(Version) {
		return
	}
	if !ui.CanPromptInteractively() {
		return
	}
	offerWindowsInstallSetup(Version, updater.CurrentExecutablePath(), true, false, false)
}
