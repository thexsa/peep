package updater

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	windowsInstallStateFile = "windows_install.json"
	windowsInstallScriptURL = "https://raw.githubusercontent.com/" + githubRepo + "/main/install.ps1"
)

// WindowsInstallState records whether user-scope Windows PATH setup has been
// completed or whether the one-time first-run prompt was dismissed.
type WindowsInstallState struct {
	Installed         bool      `json:"installed"`
	InstallDir        string    `json:"install_dir,omitempty"`
	DismissedFirstRun bool      `json:"dismissed_first_run,omitempty"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// DefaultWindowsInstallDir resolves the non-admin Windows installation folder,
// matching install.ps1 (%LOCALAPPDATA%\Programs\peep, or ~/.local/bin fallback).
func DefaultWindowsInstallDir() string {
	home, _ := os.UserHomeDir()
	return resolveWindowsInstallDir(
		os.Getenv("PEEP_INSTALL_DIR"),
		os.Getenv("LOCALAPPDATA"),
		home,
	)
}

func resolveWindowsInstallDir(overrideDir, localAppData, homeDir string) string {
	if d := strings.TrimSpace(overrideDir); d != "" {
		return filepath.Clean(d)
	}
	if lad := strings.TrimSpace(localAppData); lad != "" {
		return filepath.Join(lad, "Programs", "peep")
	}
	if h := strings.TrimSpace(homeDir); h != "" {
		return filepath.Join(h, ".local", "bin")
	}
	return filepath.Join(".", "peep")
}

// CurrentExecutablePath returns the resolved path of the running binary.
func CurrentExecutablePath() string {
	execPath, err := os.Executable()
	if err != nil {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(execPath); err == nil {
		return resolved
	}
	return execPath
}

// IsWindowsInstalled reports whether peep is already installed as peep.exe on
// the user's PATH (or in the standard user-scope install directory).
func IsWindowsInstalled() bool {
	if runtime.GOOS != "windows" {
		return true
	}
	execPath := CurrentExecutablePath()
	installDir := DefaultWindowsInstallDir()
	cacheDir, _ := CacheDir()
	return isWindowsInstalledWith(execPath, os.Getenv("PATH"), installDir, cacheDir)
}

func isWindowsInstalledWith(execPath, pathEnv, installDir, cacheDir string) bool {
	base := winPathBase(execPath)
	dirs := splitWindowsPathEnv(pathEnv)

	hasPeepOnPath := false
	installDirOnPath := false
	for _, dir := range dirs {
		if sameWinPath(dir, installDir) {
			installDirOnPath = true
		}
		candidate := filepath.Join(dir, "peep.exe")
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			hasPeepOnPath = true
		}
	}

	// 1. User is already running peep.exe and peep.exe resolves from PATH
	// (covers install.ps1, Scoop, Winget, Chocolatey, or manual PATH setup).
	if strings.EqualFold(base, "peep.exe") && hasPeepOnPath {
		return true
	}

	// 2. Standard user-scope install binary exists and its directory is in PATH.
	defaultExe := filepath.Join(installDir, "peep.exe")
	if info, err := os.Stat(defaultExe); err == nil && !info.IsDir() && installDirOnPath {
		return true
	}

	// 3. Setup was completed in the current terminal session (User PATH registry
	// was updated, though this shell's in-memory %PATH% hasn't refreshed yet)
	// and the installed peep.exe still exists on disk.
	if cacheDir != "" {
		if st, err := readWindowsInstallStateFromDir(cacheDir); err == nil && st.Installed {
			checkDir := st.InstallDir
			if strings.TrimSpace(checkDir) == "" {
				checkDir = installDir
			}
			installedExe := filepath.Join(checkDir, "peep.exe")
			if info, statErr := os.Stat(installedExe); statErr == nil && !info.IsDir() {
				return true
			}
		}
	}

	return false
}

// ShouldOfferFirstRunWindowsInstall returns true on Windows when peep is a
// release binary that has not yet been installed onto the user's PATH and the
// user has not previously dismissed the one-time first-run setup prompt.
func ShouldOfferFirstRunWindowsInstall(currentVersion string) bool {
	if runtime.GOOS != "windows" {
		return false
	}
	cacheDir, _ := CacheDir()
	return shouldOfferFirstRunWith(
		currentVersion,
		os.Getenv("PEEP_NO_INSTALL_PROMPT"),
		CurrentExecutablePath(),
		os.Getenv("PATH"),
		DefaultWindowsInstallDir(),
		cacheDir,
	)
}

func shouldOfferFirstRunWith(currentVersion, noPromptEnv, execPath, pathEnv, installDir, cacheDir string) bool {
	if currentVersion == "" || currentVersion == "dev" {
		return false
	}
	if strings.TrimSpace(noPromptEnv) != "" {
		return false
	}
	if isWindowsInstalledWith(execPath, pathEnv, installDir, cacheDir) {
		return false
	}
	if cacheDir != "" {
		if st, err := readWindowsInstallStateFromDir(cacheDir); err == nil && st.DismissedFirstRun {
			return false
		}
	}
	return true
}

// DismissWindowsInstallPrompt records that the user declined the one-time
// first-run Windows setup prompt so normal commands will not ask again.
func DismissWindowsInstallPrompt() error {
	dir, err := CacheDir()
	if err != nil {
		return err
	}
	return dismissWindowsInstallPromptInDir(dir)
}

func dismissWindowsInstallPromptInDir(cacheDir string) error {
	st, _ := readWindowsInstallStateFromDir(cacheDir)
	if st == nil {
		st = &WindowsInstallState{}
	}
	st.DismissedFirstRun = true
	st.UpdatedAt = time.Now()
	return writeWindowsInstallStateToDir(cacheDir, st)
}

// MarkWindowsInstalled records that Windows user-scope setup completed.
func MarkWindowsInstalled(installDir string) error {
	dir, err := CacheDir()
	if err != nil {
		return err
	}
	return markWindowsInstalledInDir(dir, installDir)
}

func markWindowsInstalledInDir(cacheDir, installDir string) error {
	st, _ := readWindowsInstallStateFromDir(cacheDir)
	if st == nil {
		st = &WindowsInstallState{}
	}
	st.Installed = true
	st.InstallDir = installDir
	st.UpdatedAt = time.Now()
	return writeWindowsInstallStateToDir(cacheDir, st)
}

func readWindowsInstallStateFromDir(cacheDir string) (*WindowsInstallState, error) {
	path := filepath.Join(cacheDir, windowsInstallStateFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var st WindowsInstallState
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func writeWindowsInstallStateToDir(cacheDir string, st *WindowsInstallState) error {
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(cacheDir, windowsInstallStateFile)
	return os.WriteFile(path, data, 0644)
}

// RunWindowsInstall runs the non-admin Windows installation (executing
// install.ps1 via PowerShell with SHA-256 verification and falling back to a
// native local user-scope install + User PATH update when offline or restricted).
// If allowReuseSourceExe is true, install.ps1 can reuse sourceExecPath when its
// SHA-256 matches the release checksum instead of downloading the binary twice.
func RunWindowsInstall(targetVersion, sourceExecPath string, allowReuseSourceExe bool, out io.Writer) (string, error) {
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("Windows installer is only supported on Windows")
	}
	if out == nil {
		out = os.Stdout
	}

	installDir := DefaultWindowsInstallDir()
	execPath := strings.TrimSpace(sourceExecPath)
	if execPath == "" {
		execPath = CurrentExecutablePath()
	}
	normVer := NormalizeVersion(targetVersion)

	// 1. Primary path: invoke install.ps1 via PowerShell.
	if psExe := findPowerShellExecutable(); psExe != "" {
		psCmd := "[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12; " +
			"irm '" + windowsInstallScriptURL + "' | iex"
		cmd := execCommand(psExe, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", psCmd)
		env := append([]string{}, os.Environ()...)
		env = append(env, "PEEP_INSTALL_DIR="+installDir)
		if normVer != "" && normVer != "dev" {
			env = append(env, "PEEP_VERSION=v"+normVer)
		}
		if allowReuseSourceExe && execPath != "" {
			env = append(env, "PEEP_SOURCE_BINARY="+execPath)
		}
		cmd.Env = env
		cmd.Stdout = out
		cmd.Stderr = out

		if err := cmd.Run(); err == nil {
			destExe := filepath.Join(installDir, "peep.exe")
			if info, statErr := os.Stat(destExe); statErr == nil && !info.IsDir() {
				_ = MarkWindowsInstalled(installDir)
				return installDir, nil
			}
		}
		fmt.Fprintln(out, "  [WARN] Remote install.ps1 could not complete; applying built-in local user-scope setup...")
	}

	// 2. Fallback path: native user-scope install (offline / proxy / GPO safe).
	if err := installWindowsUserLocal(execPath, installDir, normVer, allowReuseSourceExe, out); err != nil {
		return "", err
	}
	_ = MarkWindowsInstalled(installDir)
	return installDir, nil
}

func findPowerShellExecutable() string {
	if p, err := exec.LookPath("powershell.exe"); err == nil {
		return p
	}
	if sysRoot := strings.TrimSpace(os.Getenv("SystemRoot")); sysRoot != "" {
		candidate := filepath.Join(sysRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	if p, err := exec.LookPath("pwsh.exe"); err == nil {
		return p
	}
	return ""
}

func installWindowsUserLocal(execPath, installDir, normVer string, useCurrentExe bool, out io.Writer) error {
	if err := os.MkdirAll(installDir, 0755); err != nil {
		return fmt.Errorf("cannot create user install directory %q: %w", installDir, err)
	}

	destExe := filepath.Join(installDir, "peep.exe")
	tmpFile, err := os.CreateTemp(installDir, "peep-install-*.tmp")
	if err != nil {
		return fmt.Errorf("cannot write to user install directory %q: %w", installDir, err)
	}
	tmpPath := tmpFile.Name()
	defer func() {
		if _, statErr := os.Stat(tmpPath); statErr == nil {
			_ = os.Remove(tmpPath)
		}
	}()

	if !useCurrentExe && normVer != "" && normVer != "dev" {
		// Download the target release binary directly when the current binary
		// could not be updated in-place (e.g. read-only folder).
		downloadURL, urlErr := findAssetURL(normVer, binaryAssetName())
		if urlErr != nil {
			tmpFile.Close()
			return urlErr
		}
		client := &http.Client{Timeout: 120 * time.Second}
		resp, dlErr := client.Get(downloadURL)
		if dlErr != nil {
			tmpFile.Close()
			return fmt.Errorf("failed to download release binary: %w", dlErr)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			tmpFile.Close()
			return fmt.Errorf("download returned HTTP %d", resp.StatusCode)
		}
		if _, copyErr := io.Copy(tmpFile, resp.Body); copyErr != nil {
			tmpFile.Close()
			return fmt.Errorf("failed to save binary: %w", copyErr)
		}
		tmpFile.Close()
	} else {
		if execPath == "" {
			tmpFile.Close()
			return fmt.Errorf("cannot locate current executable to copy")
		}
		src, openErr := os.Open(execPath)
		if openErr != nil {
			tmpFile.Close()
			return fmt.Errorf("cannot read current executable: %w", openErr)
		}
		_, copyErr := io.Copy(tmpFile, src)
		src.Close()
		tmpFile.Close()
		if copyErr != nil {
			return fmt.Errorf("failed to copy executable: %w", copyErr)
		}
	}

	_ = os.Chmod(tmpPath, 0755)

	oldExe := destExe + ".old"
	_ = os.Remove(oldExe)
	if _, err := os.Stat(destExe); err == nil {
		if rmErr := os.Remove(destExe); rmErr != nil {
			if renErr := os.Rename(destExe, oldExe); renErr != nil {
				return fmt.Errorf("cannot replace existing %q: %w", destExe, renErr)
			}
		}
	}
	if err := os.Rename(tmpPath, destExe); err != nil {
		_ = os.Rename(oldExe, destExe)
		return fmt.Errorf("cannot install %q: %w", destExe, err)
	}
	_ = os.Remove(oldExe)

	// Best-effort removal of Mark-of-the-Web NTFS Alternate Data Stream so
	// Windows SmartScreen does not block non-admin execution.
	_ = os.Remove(destExe + ":Zone.Identifier")

	fmt.Fprintf(out, "[OK] Installed peep.exe to %s\n", destExe)

	skipPath := strings.EqualFold(os.Getenv("PEEP_NO_PATH"), "1") ||
		strings.EqualFold(os.Getenv("PEEP_NO_PATH"), "true")
	if !skipPath {
		if err := ensureWindowsUserPath(installDir); err != nil {
			fmt.Fprintf(out, "[WARN] Could not persist user PATH automatically: %s\n", err)
			fmt.Fprintf(out, "  Add '%s' to your Windows User PATH manually.\n", installDir)
		} else {
			fmt.Fprintf(out, "[OK] Added '%s' to your Windows user PATH\n", installDir)
		}
	}

	return nil
}

func ensureWindowsUserPath(installDir string) error {
	// 1. Prefer .NET [Environment]::SetEnvironmentVariable('Path', ..., 'User')
	// via PowerShell because it broadcasts WM_SETTINGCHANGE automatically.
	if psExe := findPowerShellExecutable(); psExe != "" {
		psOneLiner := `$target = $env:PEEP_TARGET_DIR.TrimEnd('\'); ` +
			`$cur = [Environment]::GetEnvironmentVariable('Path', 'User'); ` +
			`$parts = @(); if (-not [string]::IsNullOrWhiteSpace($cur)) { $parts = ($cur -split ';') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } }; ` +
			`$exists = $false; foreach ($p in $parts) { if ($p.Trim().TrimEnd('\').Equals($target, [StringComparison]::OrdinalIgnoreCase)) { $exists = $true; break } }; ` +
			`if (-not $exists) { $next = if ($parts.Count -eq 0) { $env:PEEP_TARGET_DIR } else { ($parts + $env:PEEP_TARGET_DIR) -join ';' }; [Environment]::SetEnvironmentVariable('Path', $next, 'User') }`
		cmd := execCommand(psExe, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", psOneLiner)
		cmd.Env = append(append([]string{}, os.Environ()...), "PEEP_TARGET_DIR="+installDir)
		if err := cmd.Run(); err == nil {
			return nil
		}
	}

	// 2. Fallback to built-in reg.exe against HKCU\Environment (no admin needed).
	var existing string
	outBytes, err := execCommand("reg.exe", "query", `HKCU\Environment`, "/v", "Path").Output()
	if err == nil {
		existing = parseRegQueryPathOutput(string(outBytes))
	}
	merged, changed := mergeUserPathValue(existing, installDir)
	if !changed {
		return nil
	}
	addCmd := execCommand("reg.exe", "add", `HKCU\Environment`, "/v", "Path", "/t", "REG_EXPAND_SZ", "/d", merged, "/f")
	if out, addErr := addCmd.CombinedOutput(); addErr != nil {
		return fmt.Errorf("%w (%s)", addErr, strings.TrimSpace(string(out)))
	}
	return nil
}

func parseRegQueryPathOutput(raw string) string {
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		upper := strings.ToUpper(trimmed)
		if !strings.HasPrefix(upper, "PATH ") && !strings.HasPrefix(upper, "PATH\t") {
			continue
		}
		for _, regType := range []string{"REG_EXPAND_SZ", "REG_SZ"} {
			if idx := strings.Index(upper, regType); idx != -1 {
				return strings.TrimSpace(trimmed[idx+len(regType):])
			}
		}
	}
	return ""
}

func mergeUserPathValue(existingPath, installDir string) (string, bool) {
	dirs := splitWindowsPathEnv(existingPath)
	for _, d := range dirs {
		if sameWinPath(d, installDir) {
			return existingPath, false
		}
	}
	cleanExisting := strings.TrimRight(strings.TrimSpace(existingPath), "; ")
	if cleanExisting == "" {
		return installDir, true
	}
	return cleanExisting + ";" + installDir, true
}

func splitWindowsPathEnv(pathEnv string) []string {
	var out []string
	for _, part := range strings.Split(pathEnv, ";") {
		cleaned := strings.Trim(strings.TrimSpace(part), `"`)
		if cleaned == "" || cleaned == "." || cleaned == `.\` || cleaned == "./" {
			continue
		}
		out = append(out, cleaned)
	}
	return out
}

func winPathBase(p string) string {
	normalized := strings.ReplaceAll(strings.Trim(strings.TrimSpace(p), `"`), `\`, `/`)
	normalized = strings.TrimRight(normalized, "/")
	if idx := strings.LastIndexByte(normalized, '/'); idx != -1 {
		return normalized[idx+1:]
	}
	return normalized
}

func sameWinPath(a, b string) bool {
	na := normalizeWinPathForCompare(a)
	nb := normalizeWinPathForCompare(b)
	return na != "" && strings.EqualFold(na, nb)
}

func normalizeWinPathForCompare(p string) string {
	s := strings.ReplaceAll(strings.Trim(strings.TrimSpace(p), `"`), `\`, `/`)
	for strings.Contains(s, "//") {
		s = strings.ReplaceAll(s, "//", "/")
	}
	if len(s) > 3 || (len(s) > 1 && s[1] != ':') {
		s = strings.TrimRight(s, "/")
	}
	return s
}
