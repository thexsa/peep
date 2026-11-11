package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseTargetAndHostOnly(t *testing.T) {
	tests := []struct {
		input    string
		wantHost string
		wantPort string
	}{
		{"example.com", "example.com", "443"},
		{"example.com:8443", "example.com", "8443"},
		{"https://example.com/login?foo=1", "example.com", "443"},
		{"https://example.com:9443/api/v1", "example.com", "9443"},
		{"192.0.2.42", "192.0.2.42", "443"},
		{"192.0.2.42:636", "192.0.2.42", "636"},
		{"[2001:db8::1]:8443", "2001:db8::1", "8443"},
		{"[2001:db8::1]", "2001:db8::1", "443"},
		{"https://[::1]:8443/health", "::1", "8443"},
		{"2001:db8::1", "2001:db8::1", "443"},
		{"::1", "::1", "443"},
	}

	for _, tc := range tests {
		gotHost, gotPort := parseTarget(tc.input)
		if gotHost != tc.wantHost || gotPort != tc.wantPort {
			t.Errorf("parseTarget(%q) = (%q, %q), want (%q, %q)",
				tc.input, gotHost, gotPort, tc.wantHost, tc.wantPort)
		}

		gotOnly := parseHostOnly(tc.input)
		if gotOnly != tc.wantHost {
			t.Errorf("parseHostOnly(%q) = %q, want %q", tc.input, gotOnly, tc.wantHost)
		}
	}
}

func TestDetectShellFromEnv(t *testing.T) {
	makeEnv := func(vars map[string]string) func(string) string {
		return func(k string) string {
			return vars[k]
		}
	}

	tests := []struct {
		name string
		goos string
		env  map[string]string
		want string
	}{
		{
			name: "Windows PowerShell default even with PSModulePath",
			goos: "windows",
			env:  map[string]string{"PSModulePath": `C:\Program Files\WindowsPowerShell\Modules`},
			want: "powershell",
		},
		{
			name: "Windows Git Bash via SHELL",
			goos: "windows",
			env: map[string]string{
				"SHELL":        "/usr/bin/bash",
				"PSModulePath": `C:\Program Files\WindowsPowerShell\Modules`,
			},
			want: "bash",
		},
		{
			name: "Windows MSYS2 via MSYSTEM without SHELL",
			goos: "windows",
			env:  map[string]string{"MSYSTEM": "MINGW64"},
			want: "bash",
		},
		{
			name: "Windows Zsh with .exe path",
			goos: "windows",
			env:  map[string]string{"SHELL": `C:\msys64\usr\bin\zsh.exe`},
			want: "zsh",
		},
		{
			name: "macOS default zsh",
			goos: "darwin",
			env:  map[string]string{"SHELL": "/bin/zsh"},
			want: "zsh",
		},
		{
			name: "macOS interactive pwsh overrides login SHELL",
			goos: "darwin",
			env: map[string]string{
				"SHELL":        "/bin/zsh",
				"PSModulePath": "/Users/dev/.local/share/powershell/Modules",
			},
			want: "powershell",
		},
		{
			name: "Linux bash",
			goos: "linux",
			env:  map[string]string{"SHELL": "/bin/bash"},
			want: "bash",
		},
		{
			name: "AIX default ksh",
			goos: "aix",
			env:  map[string]string{"SHELL": "/usr/bin/ksh"},
			want: "ksh",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := detectShellFromEnv(tc.goos, makeEnv(tc.env))
			if got != tc.want {
				t.Fatalf("detectShellFromEnv(%q) = %q, want %q", tc.goos, got, tc.want)
			}
		})
	}
}

func TestSelectBashRCFile(t *testing.T) {
	t.Run("linux always selects .bashrc", func(t *testing.T) {
		home := t.TempDir()
		got := selectBashRCFile(home, "linux")
		want := filepath.Join(home, ".bashrc")
		if got != want {
			t.Fatalf("selectBashRCFile(linux) = %q, want %q", got, want)
		}
	})

	t.Run("darwin defaults to .bash_profile when neither exists", func(t *testing.T) {
		home := t.TempDir()
		got := selectBashRCFile(home, "darwin")
		want := filepath.Join(home, ".bash_profile")
		if got != want {
			t.Fatalf("selectBashRCFile(darwin, empty) = %q, want %q", got, want)
		}
	})

	t.Run("darwin uses .bashrc when .bash_profile sources .bashrc", func(t *testing.T) {
		home := t.TempDir()
		bashrc := filepath.Join(home, ".bashrc")
		bashProfile := filepath.Join(home, ".bash_profile")
		_ = os.WriteFile(bashrc, []byte("# existing bashrc\n"), 0644)
		_ = os.WriteFile(bashProfile, []byte("[ -f ~/.bashrc ] && source ~/.bashrc\n"), 0644)

		got := selectBashRCFile(home, "darwin")
		if got != bashrc {
			t.Fatalf("selectBashRCFile(darwin, sourced .bashrc) = %q, want %q", got, bashrc)
		}
	})

	t.Run("darwin prefers .bash_profile when .bash_profile ignores .bashrc", func(t *testing.T) {
		home := t.TempDir()
		bashrc := filepath.Join(home, ".bashrc")
		bashProfile := filepath.Join(home, ".bash_profile")
		_ = os.WriteFile(bashrc, []byte("# existing bashrc\n"), 0644)
		_ = os.WriteFile(bashProfile, []byte("export PATH=/usr/local/bin:$PATH\n"), 0644)

		got := selectBashRCFile(home, "darwin")
		if got != bashProfile {
			t.Fatalf("selectBashRCFile(darwin, unsourced .bashrc) = %q, want %q", got, bashProfile)
		}
	})
}

func TestTuneWorkerConcurrency(t *testing.T) {
	if got := tuneWorkerConcurrency(0); got < 1 {
		t.Fatalf("tuneWorkerConcurrency(0) = %d, want >= 1", got)
	}
	if got := tuneWorkerConcurrency(50); got < 1 || got > 50 {
		t.Fatalf("tuneWorkerConcurrency(50) = %d, want between 1 and 50", got)
	}
}

func TestRemovedFlagAliasesAbsentAndBaseFlagsIntact(t *testing.T) {
	for _, removed := range []string{"lens", "gaze", "knock"} {
		if f := rootCmd.PersistentFlags().Lookup(removed); f != nil {
			t.Errorf("deprecated alias --%s should be removed, but is still registered on PersistentFlags", removed)
		}
		if f := rootCmd.Flags().Lookup(removed); f != nil {
			t.Errorf("deprecated alias --%s should be removed, but is still registered on Flags", removed)
		}
	}

	for _, kept := range []struct {
		long  string
		short string
	}{
		{"proto", "P"},
		{"details", "d"},
		{"connect", "c"},
	} {
		f := rootCmd.PersistentFlags().Lookup(kept.long)
		if f == nil {
			t.Fatalf("expected base flag --%s to remain registered", kept.long)
		}
		if f.Shorthand != kept.short {
			t.Errorf("flag --%s shorthand = %q, want %q", kept.long, f.Shorthand, kept.short)
		}
	}
}

func TestReleaseNotes080Present(t *testing.T) {
	notes, ok := releaseNotes["0.8.0"]
	if !ok || notes == "" {
		t.Fatalf("expected releaseNotes[\"0.8.0\"] to be populated for peep update whatsnew output")
	}
}
