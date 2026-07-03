package cli

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/thexsa/peep/internal/ui"
)

var flagCompletionInstall bool

var completionCmd = &cobra.Command{
	Use:   "completion [bash|zsh|fish|powershell]",
	Short: "Generate or install shell autocompletion",
	Long: `Generate or install shell autocompletion for peep.

Auto-install (recommended — detects your shell and sets everything up):
  peep completion --install

Or generate a completion script for a specific shell:
  peep completion bash
  peep completion zsh
  peep completion fish
  peep completion powershell

The --install flag:
  • Detects your current shell automatically
  • Writes the completion script to ~/.peep/completions/
  • Appends the necessary source line to your shell's rc file
  • NEVER overwrites — only appends if not already present
  • Supports zsh, bash, fish, and PowerShell`,
	Args:                  cobra.MaximumNArgs(1),
	DisableFlagsInUseLine: true,
	ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
	RunE: func(cmd *cobra.Command, args []string) error {
		if flagCompletionInstall {
			// If a specific shell was given, use it; otherwise auto-detect
			if len(args) == 1 {
				return installForShell(args[0])
			}
			return runCompletionInstall()
		}

		if len(args) == 0 {
			return cmd.Help()
		}

		// Generate completion script to stdout (the default behavior)
		switch args[0] {
		case "bash":
			return rootCmd.GenBashCompletionV2(os.Stdout, true)
		case "zsh":
			return rootCmd.GenZshCompletion(os.Stdout)
		case "fish":
			return rootCmd.GenFishCompletion(os.Stdout, true)
		case "powershell":
			return rootCmd.GenPowerShellCompletionWithDesc(os.Stdout)
		default:
			return fmt.Errorf("unsupported shell: %s (use bash, zsh, fish, or powershell)", args[0])
		}
	},
}

func init() {
	completionCmd.Flags().BoolVar(&flagCompletionInstall, "install", false,
		"Auto-detect your shell and install completions permanently")

	// Disable cobra's built-in completion command
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	// Add our custom one
	rootCmd.AddCommand(completionCmd)
}

// runCompletionInstall auto-detects the user's shell and installs
// tab-completion permanently.
func runCompletionInstall() error {
	shell := detectShell()
	return installForShell(shell)
}

func installForShell(shell string) error {
	switch shell {
	case "zsh":
		return installZsh()
	case "bash":
		return installBash()
	case "fish":
		return installFish()
	case "powershell", "pwsh":
		return installPowerShell()
	default:
		fmt.Println(ui.Theme.ErrorStyle.Render(
			fmt.Sprintf("\n  [FAIL] Could not detect your shell (got %q).", shell)))
		fmt.Println(ui.Theme.MutedStyle.Render(
			"         Specify the shell explicitly:"))
		fmt.Println(ui.Theme.InfoStyle.Render(
			"           peep completion zsh --install"))
		fmt.Println(ui.Theme.InfoStyle.Render(
			"           peep completion bash --install"))
		fmt.Println(ui.Theme.InfoStyle.Render(
			"           peep completion fish --install"))
		fmt.Println(ui.Theme.InfoStyle.Render(
			"           peep completion powershell --install"))
		fmt.Println()
		return nil
	}
}

func detectShell() string {
	// Windows: default to PowerShell
	if runtime.GOOS == "windows" {
		return "powershell"
	}

	// Unix: check $SHELL
	shell := os.Getenv("SHELL")
	if shell == "" {
		return "unknown"
	}
	return filepath.Base(shell)
}

// ─────────────────────────────────────────────
// Zsh
// ─────────────────────────────────────────────

func installZsh() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("could not find home directory: %w", err)
	}

	// 1. Write completion script to ~/.peep/completions/_peep
	completionDir := filepath.Join(home, ".peep", "completions")
	if err := os.MkdirAll(completionDir, 0755); err != nil {
		return fmt.Errorf("could not create %s: %w", completionDir, err)
	}

	completionFile := filepath.Join(completionDir, "_peep")
	var buf bytes.Buffer
	if err := rootCmd.GenZshCompletion(&buf); err != nil {
		return fmt.Errorf("could not generate zsh completion: %w", err)
	}
	if err := os.WriteFile(completionFile, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("could not write %s: %w", completionFile, err)
	}

	// 2. Append fpath + compinit to .zshrc (only if not already present)
	zshrc := filepath.Join(home, ".zshrc")
	marker := "# peep shell completion"
	sourceLine := fmt.Sprintf(
		"\n%s\nfpath=(%s $fpath)\nautoload -Uz compinit && compinit\n",
		marker, completionDir)

	if err := appendIfMissing(zshrc, marker, sourceLine); err != nil {
		return fmt.Errorf("could not update %s: %w", zshrc, err)
	}

	printSuccess("zsh", zshrc, "source "+zshrc)
	return nil
}

// ─────────────────────────────────────────────
// Bash
// ─────────────────────────────────────────────

func installBash() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("could not find home directory: %w", err)
	}

	// Write completion script to ~/.peep/completions/peep.bash
	completionDir := filepath.Join(home, ".peep", "completions")
	if err := os.MkdirAll(completionDir, 0755); err != nil {
		return fmt.Errorf("could not create %s: %w", completionDir, err)
	}

	completionFile := filepath.Join(completionDir, "peep.bash")
	var buf bytes.Buffer
	if err := rootCmd.GenBashCompletionV2(&buf, true); err != nil {
		return fmt.Errorf("could not generate bash completion: %w", err)
	}
	if err := os.WriteFile(completionFile, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("could not write %s: %w", completionFile, err)
	}

	// Append source line to .bashrc
	bashrc := filepath.Join(home, ".bashrc")
	marker := "# peep shell completion"
	sourceLine := fmt.Sprintf("\n%s\nsource %s\n", marker, completionFile)

	if err := appendIfMissing(bashrc, marker, sourceLine); err != nil {
		return fmt.Errorf("could not update %s: %w", bashrc, err)
	}

	printSuccess("bash", bashrc, "source "+bashrc)
	return nil
}

// ─────────────────────────────────────────────
// Fish
// ─────────────────────────────────────────────

func installFish() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("could not find home directory: %w", err)
	}

	// Fish completions auto-load from ~/.config/fish/completions/
	completionDir := filepath.Join(home, ".config", "fish", "completions")
	if err := os.MkdirAll(completionDir, 0755); err != nil {
		return fmt.Errorf("could not create %s: %w", completionDir, err)
	}

	completionFile := filepath.Join(completionDir, "peep.fish")
	var buf bytes.Buffer
	if err := rootCmd.GenFishCompletion(&buf, true); err != nil {
		return fmt.Errorf("could not generate fish completion: %w", err)
	}
	if err := os.WriteFile(completionFile, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("could not write %s: %w", completionFile, err)
	}

	// Fish auto-loads from this directory — no rc edit needed
	fmt.Println()
	fmt.Println(ui.Theme.BoldStyle.Render("  ✅ Fish completions installed!"))
	fmt.Println()
	fmt.Println(ui.Theme.MutedStyle.Render(fmt.Sprintf("  Wrote: %s", completionFile)))
	fmt.Println(ui.Theme.MutedStyle.Render("  Fish auto-loads from this directory — no config changes needed."))
	fmt.Println()
	fmt.Println(ui.Theme.InfoStyle.Render("  Restart your terminal or run:"))
	fmt.Println(ui.Theme.InfoStyle.Render("    source " + completionFile))
	fmt.Println()
	return nil
}

// ─────────────────────────────────────────────
// PowerShell
// ─────────────────────────────────────────────

func installPowerShell() error {
	// Find the PowerShell profile path
	profilePath := getPowerShellProfile()
	if profilePath == "" {
		fmt.Println(ui.Theme.ErrorStyle.Render("\n  [FAIL] Could not determine PowerShell profile path."))
		fmt.Println(ui.Theme.MutedStyle.Render("         Run this in PowerShell to find it:"))
		fmt.Println(ui.Theme.InfoStyle.Render("           echo $PROFILE"))
		fmt.Println()
		fmt.Println(ui.Theme.MutedStyle.Render("         Then add this line to your profile:"))
		fmt.Println(ui.Theme.InfoStyle.Render("           peep completion powershell | Out-String | Invoke-Expression"))
		return nil
	}

	// Ensure the profile directory exists
	profileDir := filepath.Dir(profilePath)
	if err := os.MkdirAll(profileDir, 0755); err != nil {
		return fmt.Errorf("could not create profile directory %s: %w", profileDir, err)
	}

	// Append to PowerShell profile
	marker := "# peep shell completion"
	sourceLine := fmt.Sprintf("\n%s\npeep completion powershell | Out-String | Invoke-Expression\n", marker)

	if err := appendIfMissing(profilePath, marker, sourceLine); err != nil {
		return fmt.Errorf("could not update %s: %w", profilePath, err)
	}

	fmt.Println()
	fmt.Println(ui.Theme.BoldStyle.Render("  ✅ PowerShell completions installed!"))
	fmt.Println()
	fmt.Println(ui.Theme.MutedStyle.Render(fmt.Sprintf("  Updated: %s", profilePath)))
	fmt.Println()
	fmt.Println(ui.Theme.InfoStyle.Render("  Restart PowerShell or run:"))
	fmt.Println(ui.Theme.InfoStyle.Render(fmt.Sprintf("    . %s", profilePath)))
	fmt.Println()
	fmt.Println(ui.Theme.WarningStyle.Render("  ⚠️  If you get an execution policy error, run:"))
	fmt.Println(ui.Theme.InfoStyle.Render("    Set-ExecutionPolicy RemoteSigned -Scope CurrentUser"))
	fmt.Println()
	return nil
}

func getPowerShellProfile() string {
	// Try pwsh (PowerShell Core) first, then powershell (Windows PowerShell)
	for _, ps := range []string{"pwsh", "powershell"} {
		out, err := exec.Command(ps, "-NoProfile", "-Command", "echo $PROFILE").Output()
		if err == nil {
			path := strings.TrimSpace(string(out))
			if path != "" {
				return path
			}
		}
	}
	return ""
}

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────

// appendIfMissing APPENDS content to a file ONLY if the marker string
// is not already present. Creates the file if it doesn't exist.
// NEVER overwrites existing content — always appends.
func appendIfMissing(filePath, marker, content string) error {
	// Read existing content (if file exists)
	existing, err := os.ReadFile(filePath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("could not read %s: %w", filePath, err)
	}

	// Check if already installed — skip if marker is found
	if strings.Contains(string(existing), marker) {
		return nil // already present, do nothing
	}

	// APPEND to file (O_APPEND | O_CREATE | O_WRONLY) — never truncates
	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("could not open %s for appending: %w", filePath, err)
	}
	defer f.Close()

	if _, err := f.WriteString(content); err != nil {
		return fmt.Errorf("could not append to %s: %w", filePath, err)
	}

	return nil
}

func printSuccess(shell, rcFile, reloadCmd string) {
	fmt.Println()
	fmt.Println(ui.Theme.BoldStyle.Render(fmt.Sprintf("  ✅ %s completions installed!", shell)))
	fmt.Println()
	fmt.Println(ui.Theme.MutedStyle.Render(fmt.Sprintf("  Updated: %s", rcFile)))
	fmt.Println()
	fmt.Println(ui.Theme.InfoStyle.Render("  Restart your terminal, or run:"))
	fmt.Println(ui.Theme.InfoStyle.Render(fmt.Sprintf("    %s", reloadCmd)))
	fmt.Println()
}
