package updater

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveWindowsInstallDir(t *testing.T) {
	t.Run("honors explicit PEEP_INSTALL_DIR override", func(t *testing.T) {
		got := resolveWindowsInstallDir(`  /custom/peep/bin  `, `/localappdata`, `/home/user`)
		if got != filepath.Clean("/custom/peep/bin") {
			t.Fatalf("resolveWindowsInstallDir override = %q", got)
		}
	})

	t.Run("uses LOCALAPPDATA Programs peep when set", func(t *testing.T) {
		base := t.TempDir()
		got := resolveWindowsInstallDir("", base, "/home/user")
		want := filepath.Join(base, "Programs", "peep")
		if got != want {
			t.Fatalf("resolveWindowsInstallDir(LOCALAPPDATA) = %q, want %q", got, want)
		}
	})

	t.Run("falls back to ~/.local/bin when LOCALAPPDATA empty", func(t *testing.T) {
		home := t.TempDir()
		got := resolveWindowsInstallDir("", "", home)
		want := filepath.Join(home, ".local", "bin")
		if got != want {
			t.Fatalf("resolveWindowsInstallDir(home) = %q, want %q", got, want)
		}
	})
}

func TestIsWindowsInstalledWith_Scenarios(t *testing.T) {
	t.Run("standalone peep-windows-amd64.exe in Downloads is NOT installed", func(t *testing.T) {
		downloadsDir := t.TempDir()
		installDir := filepath.Join(t.TempDir(), "Programs", "peep")
		cacheDir := t.TempDir()
		otherPathDir := t.TempDir()

		dlExe := filepath.Join(downloadsDir, "peep-windows-amd64.exe")
		_ = os.WriteFile(dlExe, []byte("exe"), 0755)

		if isWindowsInstalledWith(dlExe, otherPathDir, installDir, cacheDir) {
			t.Fatal("expected standalone peep-windows-amd64.exe in Downloads to report NOT installed")
		}
	})

	t.Run("renamed peep.exe in Downloads (not on PATH, even with dot in PATH) is NOT installed", func(t *testing.T) {
		downloadsDir := t.TempDir()
		installDir := filepath.Join(t.TempDir(), "Programs", "peep")
		cacheDir := t.TempDir()
		otherPathDir := t.TempDir()

		dlExe := filepath.Join(downloadsDir, "peep.exe")
		_ = os.WriteFile(dlExe, []byte("exe"), 0755)

		pathEnv := ".;" + `.\;` + otherPathDir
		if isWindowsInstalledWith(dlExe, pathEnv, installDir, cacheDir) {
			t.Fatal("expected peep.exe outside PATH (with '.' in PATH) to report NOT installed")
		}
	})

	t.Run("peep-windows-amd64.exe inside a PATH folder is STILL NOT installed as peep.exe", func(t *testing.T) {
		toolsDir := t.TempDir()
		installDir := filepath.Join(t.TempDir(), "Programs", "peep")
		cacheDir := t.TempDir()

		fullNamedExe := filepath.Join(toolsDir, "peep-windows-amd64.exe")
		_ = os.WriteFile(fullNamedExe, []byte("exe"), 0755)

		if isWindowsInstalledWith(fullNamedExe, toolsDir, installDir, cacheDir) {
			t.Fatal("expected peep-windows-amd64.exe (without peep.exe) to report NOT installed")
		}
	})

	t.Run("peep.exe inside a PATH directory (install.ps1, Scoop, Winget, custom dir) IS installed", func(t *testing.T) {
		toolsDir := t.TempDir()
		installDir := filepath.Join(t.TempDir(), "Programs", "peep")
		cacheDir := t.TempDir()

		installedExe := filepath.Join(toolsDir, "peep.exe")
		_ = os.WriteFile(installedExe, []byte("exe"), 0755)

		quotedPathEnv := `"` + toolsDir + `";/usr/bin`
		if !isWindowsInstalledWith(installedExe, quotedPathEnv, installDir, cacheDir) {
			t.Fatal("expected peep.exe on PATH to report installed")
		}
	})

	t.Run("same-terminal session after setup reports installed until peep.exe is removed", func(t *testing.T) {
		downloadsDir := t.TempDir()
		installDir := filepath.Join(t.TempDir(), "Programs", "peep")
		cacheDir := t.TempDir()
		_ = os.MkdirAll(installDir, 0755)

		dlExe := filepath.Join(downloadsDir, "peep-windows-amd64.exe")
		destExe := filepath.Join(installDir, "peep.exe")
		_ = os.WriteFile(dlExe, []byte("exe"), 0755)
		_ = os.WriteFile(destExe, []byte("exe"), 0755)

		if err := markWindowsInstalledInDir(cacheDir, installDir); err != nil {
			t.Fatalf("markWindowsInstalledInDir error: %v", err)
		}

		// Even before the current cmd.exe refreshes %PATH%, state + existing destExe reports installed.
		if !isWindowsInstalledWith(dlExe, "", installDir, cacheDir) {
			t.Fatal("expected state + existing peep.exe to report installed in same session")
		}

		// If the user deletes peep.exe manually, it self-heals back to not installed.
		_ = os.Remove(destExe)
		if isWindowsInstalledWith(dlExe, "", installDir, cacheDir) {
			t.Fatal("expected deleting peep.exe to reset installed check to false")
		}
	})
}

func TestShouldOfferFirstRunWith_DismissalAndUpdateSeparation(t *testing.T) {
	downloadsDir := t.TempDir()
	installDir := filepath.Join(t.TempDir(), "Programs", "peep")
	cacheDir := t.TempDir()
	dlExe := filepath.Join(downloadsDir, "peep-windows-amd64.exe")
	_ = os.WriteFile(dlExe, []byte("exe"), 0755)

	// 1. Dev builds and empty versions never prompt on normal runs.
	if shouldOfferFirstRunWith("dev", "", dlExe, "", installDir, cacheDir) {
		t.Fatal("expected dev build to skip first-run prompt")
	}
	if shouldOfferFirstRunWith("", "", dlExe, "", installDir, cacheDir) {
		t.Fatal("expected empty version to skip first-run prompt")
	}

	// 2. PEEP_NO_INSTALL_PROMPT suppresses first-run prompt.
	if shouldOfferFirstRunWith("0.8.1", "1", dlExe, "", installDir, cacheDir) {
		t.Fatal("expected PEEP_NO_INSTALL_PROMPT=1 to skip first-run prompt")
	}

	// 3. Fresh standalone release binary (e.g. first run after updating from v0.7.0) SHOULD prompt.
	if !shouldOfferFirstRunWith("0.8.1", "", dlExe, "", installDir, cacheDir) {
		t.Fatal("expected first run of un-installed release binary to offer setup")
	}

	// 4. Declining first-run suppresses future normal runs, while isWindowsInstalledWith
	// stays false so `peep update` going forward can still offer setup.
	if err := dismissWindowsInstallPromptInDir(cacheDir); err != nil {
		t.Fatalf("dismissWindowsInstallPromptInDir error: %v", err)
	}
	if shouldOfferFirstRunWith("0.8.1", "", dlExe, "", installDir, cacheDir) {
		t.Fatal("expected dismissed first-run state to suppress subsequent normal-run prompts")
	}
	if isWindowsInstalledWith(dlExe, "", installDir, cacheDir) {
		t.Fatal("expected isWindowsInstalledWith to remain false after dismissal so peep update still offers setup")
	}
}

func TestMergeUserPathValueAndRegOutput(t *testing.T) {
	rawReg := "\r\nHKEY_CURRENT_USER\\Environment\r\n    Path    REG_EXPAND_SZ    %USERPROFILE%\\AppData\\Local\\Microsoft\\WindowsApps;C:\\Tools\r\n\r\n"
	got := parseRegQueryPathOutput(rawReg)
	want := `%USERPROFILE%\AppData\Local\Microsoft\WindowsApps;C:\Tools`
	if got != want {
		t.Fatalf("parseRegQueryPathOutput = %q, want %q", got, want)
	}

	// Appends when absent, preserving unexpanded %USERPROFILE%.
	merged, changed := mergeUserPathValue(got, `C:\Users\alice\AppData\Local\Programs\peep`)
	if !changed {
		t.Fatal("expected mergeUserPathValue to report changed=true when dir is absent")
	}
	if !strings.HasPrefix(merged, want+";") {
		t.Fatalf("unexpected merged PATH: %q", merged)
	}

	// Case-insensitive + trailing backslash deduplication.
	_, changedAgain := mergeUserPathValue(merged, `c:\users\alice\appdata\local\programs\peep\`)
	if changedAgain {
		t.Fatal("expected duplicate directory (different case + trailing backslash) not to be re-added")
	}

	// Empty existing User PATH.
	fresh, freshChanged := mergeUserPathValue("", `C:\Users\alice\AppData\Local\Programs\peep`)
	if !freshChanged || fresh != `C:\Users\alice\AppData\Local\Programs\peep` {
		t.Fatalf("unexpected merge for empty User PATH: %q (changed=%v)", fresh, freshChanged)
	}
}

func TestInstallWindowsUserLocal_CopiesBinary(t *testing.T) {
	t.Setenv("PEEP_NO_PATH", "1")
	srcDir := t.TempDir()
	installDir := filepath.Join(t.TempDir(), "Programs", "peep")

	srcExe := filepath.Join(srcDir, "peep-windows-amd64.exe")
	payload := []byte("simulated-peep-windows-binary")
	if err := os.WriteFile(srcExe, payload, 0755); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	var out bytes.Buffer
	if err := installWindowsUserLocal(srcExe, installDir, "0.8.1", true, &out); err != nil {
		t.Fatalf("installWindowsUserLocal error: %v", err)
	}

	destExe := filepath.Join(installDir, "peep.exe")
	gotBytes, err := os.ReadFile(destExe)
	if err != nil {
		t.Fatalf("expected %s to exist: %v", destExe, err)
	}
	if !bytes.Equal(gotBytes, payload) {
		t.Fatalf("installed binary content mismatch: got %q, want %q", gotBytes, payload)
	}
	if !strings.Contains(out.String(), "[OK] Installed peep.exe") {
		t.Fatalf("expected [OK] confirmation in output, got: %s", out.String())
	}
}
