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

// execCommand is a variable so it can be overridden in tests.
var execCommand = exec.Command

// InstallMethod describes how peep was installed.
type InstallMethod int

const (
	// InstallGitHubBinary means peep was downloaded as a standalone binary.
	InstallGitHubBinary InstallMethod = iota
	// InstallHomebrew means peep was installed via Homebrew.
	InstallHomebrew
	// InstallDevBuild means peep was built from source without version tags.
	InstallDevBuild
)

// String returns a human-readable name for the install method.
func (m InstallMethod) String() string {
	switch m {
	case InstallGitHubBinary:
		return "GitHub binary"
	case InstallHomebrew:
		return "Homebrew"
	case InstallDevBuild:
		return "dev build"
	default:
		return "unknown"
	}
}

// UpdateInfo holds the result of a version check against GitHub.
type UpdateInfo struct {
	CurrentVersion  string        `json:"current_version"`
	LatestVersion   string        `json:"latest_version"`
	UpdateAvailable bool          `json:"update_available"`
	ReleaseURL      string        `json:"release_url"`
	InstallMethod   InstallMethod `json:"install_method"`
	Force           bool          `json:"-"` // when true, reinstall even if same version
}

// githubRelease is the subset of the GitHub API response we need.
type githubRelease struct {
	TagName string        `json:"tag_name"`
	HTMLURL string        `json:"html_url"`
	Assets  []githubAsset `json:"assets"`
}

type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

const (
	githubRepo    = "thexsa/peep"
	githubAPIURL  = "https://api.github.com/repos/" + githubRepo + "/releases/latest"
	brewFormula   = "thexsa/tap/peep"
	updateTimeout = 10 * time.Second
)

// CheckForUpdate queries the GitHub Releases API for the latest version
// and compares it with the current version.
func CheckForUpdate(currentVersion string) (*UpdateInfo, error) {
	method := DetectInstallMethod(currentVersion)

	info := &UpdateInfo{
		CurrentVersion: NormalizeVersion(currentVersion),
		InstallMethod:  method,
	}

	client := &http.Client{Timeout: updateTimeout}
	req, err := http.NewRequest("GET", githubAPIURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "peep/"+currentVersion)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to check for updates: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned HTTP %d", resp.StatusCode)
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("failed to parse GitHub response: %w", err)
	}

	info.LatestVersion = NormalizeVersion(release.TagName)
	info.ReleaseURL = release.HTMLURL
	info.UpdateAvailable = IsNewer(info.CurrentVersion, info.LatestVersion)

	return info, nil
}

// DetectInstallMethod determines how peep was installed by examining
// the path of the running binary.
func DetectInstallMethod(currentVersion string) InstallMethod {
	if currentVersion == "dev" || currentVersion == "" {
		return InstallDevBuild
	}

	execPath, err := os.Executable()
	if err != nil {
		return InstallGitHubBinary
	}

	// Resolve symlinks to find the real path
	resolvedPath, err := filepath.EvalSymlinks(execPath)
	if err != nil {
		resolvedPath = execPath
	}

	lower := strings.ToLower(resolvedPath)

	// Homebrew paths: /opt/homebrew/Cellar/, /usr/local/Cellar/,
	// /home/linuxbrew/.linuxbrew/Cellar/
	if strings.Contains(lower, "cellar") ||
		strings.Contains(lower, "homebrew") ||
		strings.Contains(lower, "linuxbrew") {
		return InstallHomebrew
	}

	return InstallGitHubBinary
}

// PerformUpdate downloads and installs the latest version of peep.
// For Homebrew installs, it runs `brew upgrade` (or `brew reinstall` with --force).
// For GitHub binaries, it downloads the correct platform binary and replaces the current one.
func PerformUpdate(info *UpdateInfo) error {
	switch info.InstallMethod {
	case InstallHomebrew:
		return updateViaHomebrew(info.Force)
	case InstallGitHubBinary:
		return updateViaGitHub(info)
	case InstallDevBuild:
		return fmt.Errorf("dev build detected — update from source: git pull && make build")
	default:
		return fmt.Errorf("unknown install method")
	}
}

// updateViaHomebrew runs brew upgrade (or reinstall with --force) to update peep.
func updateViaHomebrew(force bool) error {
	brewCmd := "upgrade"
	if force {
		brewCmd = "reinstall"
	}
	cmd := execCommand("brew", brewCmd, brewFormula)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// updateViaGitHub downloads the latest release binary from GitHub
// and replaces the current executable.
func updateViaGitHub(info *UpdateInfo) error {
	assetName := binaryAssetName()

	// Find the matching asset URL
	downloadURL, err := findAssetURL(info.LatestVersion, assetName)
	if err != nil {
		return err
	}

	// Download to a temp file
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Get(downloadURL)
	if err != nil {
		return fmt.Errorf("failed to download update: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned HTTP %d", resp.StatusCode)
	}

	// Get current executable path
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot determine executable path: %w", err)
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return fmt.Errorf("cannot resolve executable path: %w", err)
	}

	// Write to temp file in the same directory (for atomic rename)
	dir := filepath.Dir(execPath)
	tmpFile, err := os.CreateTemp(dir, "peep-update-*")
	if err != nil {
		return fmt.Errorf("cannot create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	// Clean up temp file on error
	defer func() {
		if _, statErr := os.Stat(tmpPath); statErr == nil {
			os.Remove(tmpPath)
		}
	}()

	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to write update: %w", err)
	}
	tmpFile.Close()

	// Make executable
	if err := os.Chmod(tmpPath, 0755); err != nil {
		return fmt.Errorf("cannot set executable permission: %w", err)
	}

	// Replace the current binary
	if runtime.GOOS == "windows" {
		// Windows: can't replace a running executable directly.
		// Rename current to .old, then rename new to current.
		oldPath := execPath + ".old"
		os.Remove(oldPath) // remove any previous .old file
		if err := os.Rename(execPath, oldPath); err != nil {
			return fmt.Errorf("cannot rename current binary: %w", err)
		}
		if err := os.Rename(tmpPath, execPath); err != nil {
			// Try to restore the old binary
			os.Rename(oldPath, execPath)
			return fmt.Errorf("cannot install new binary: %w", err)
		}
		// Best-effort cleanup of the old binary
		os.Remove(oldPath)
	} else {
		// Unix: atomic rename
		if err := os.Rename(tmpPath, execPath); err != nil {
			return fmt.Errorf("cannot replace binary: %w", err)
		}
	}

	return nil
}

// findAssetURL queries the GitHub release for the correct binary asset URL.
func findAssetURL(version, assetName string) (string, error) {
	// Construct the direct download URL for the release asset
	tag := "v" + version
	url := fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", githubRepo, tag, assetName)

	// Verify the URL is reachable with a HEAD request
	client := &http.Client{Timeout: updateTimeout}
	resp, err := client.Head(url)
	if err != nil {
		return "", fmt.Errorf("cannot reach download URL: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusTemporaryRedirect {
		return url, nil
	}

	return "", fmt.Errorf("asset %q not found in release v%s (HTTP %d)", assetName, version, resp.StatusCode)
}

// binaryAssetName returns the expected GitHub release asset name
// for the current platform.
func binaryAssetName() string {
	name := fmt.Sprintf("peep-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return name
}

// NormalizeVersion strips a leading "v" from version strings.
func NormalizeVersion(v string) string {
	return strings.TrimPrefix(v, "v")
}

// IsNewer returns true if latest is a newer version than current.
// Uses simple lexicographic comparison on dot-separated segments
// after normalizing. Falls back to string comparison for non-standard formats.
func IsNewer(current, latest string) bool {
	if current == "" || current == "dev" {
		return false
	}
	if current == latest {
		return false
	}

	cParts := strings.Split(current, ".")
	lParts := strings.Split(latest, ".")

	maxLen := len(cParts)
	if len(lParts) > maxLen {
		maxLen = len(lParts)
	}

	for i := 0; i < maxLen; i++ {
		var cVal, lVal int
		if i < len(cParts) {
			fmt.Sscanf(cParts[i], "%d", &cVal)
		}
		if i < len(lParts) {
			fmt.Sscanf(lParts[i], "%d", &lVal)
		}
		if lVal > cVal {
			return true
		}
		if lVal < cVal {
			return false
		}
	}
	return false
}
