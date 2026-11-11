# install.ps1 -- Install the peep binary on Windows (non-admin friendly).
#
# Usage (PowerShell 5.1+ or pwsh 7+, no Administrator privileges required):
#   irm https://raw.githubusercontent.com/thexsa/peep/main/install.ps1 | iex
#
# Optional environment overrides before running:
#   $env:PEEP_INSTALL_DIR = "$HOME\bin"       # Custom user-writable directory
#   $env:PEEP_VERSION     = "v0.8.0"          # Pin a specific release tag
#   $env:PEEP_NO_PATH     = "1"               # Skip modifying user PATH
#
# Or run locally with flags:
#   .\install.ps1 -InstallDir "$HOME\bin" -Version "v0.8.0" -NoModifyPath

function Install-Peep {
    [CmdletBinding()]
    param(
        [string]$InstallDir = $env:PEEP_INSTALL_DIR,
        [string]$Version    = $env:PEEP_VERSION,
        [switch]$NoModifyPath
    )

    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'
    $Repo = 'thexsa/peep'

    function Write-Info([string]$Msg) { Write-Host "  $Msg" }
    function Write-Ok([string]$Msg)   { Write-Host "[OK] $Msg" -ForegroundColor Green }
    function Write-Warn([string]$Msg) { Write-Host "[WARN] $Msg" -ForegroundColor Yellow }
    function Write-Fail([string]$Msg) { Write-Host "[FAIL] $Msg" -ForegroundColor Red }

    # Ensure TLS 1.2 is enabled for Windows PowerShell 5.1 on older systems.
    try {
        [Net.ServicePointManager]::SecurityProtocol = `
            [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    } catch {
        # Modern .NET / PowerShell 7+ manages TLS versions automatically.
    }

    # Verify Windows OS when running under cross-platform pwsh 7+.
    if ($PSVersionTable.PSVersion.Major -ge 6 -and -not $IsWindows) {
        Write-Fail "install.ps1 is for Windows. On macOS, Linux, or AIX, run:"
        Write-Info "curl -sSfL https://raw.githubusercontent.com/$Repo/main/install.sh | sh"
        return
    }

    # Detect native OS CPU architecture (handles x64/x86 WOW64 emulation on Windows on ARM).
    $Arch = $null
    try {
        $osArch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToUpperInvariant()
        switch ($osArch) {
            'ARM64' { $Arch = 'arm64' }
            'X64'   { $Arch = 'amd64' }
        }
    } catch {
        # Fallback for older .NET Framework runtimes (< 4.7.1)
    }

    if (-not $Arch) {
        $rawArch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
        switch -Wildcard ($rawArch) {
            '*ARM64*' { $Arch = 'arm64' }
            '*AMD64*' { $Arch = 'amd64' }
            '*x86_64*'{ $Arch = 'amd64' }
            default {
                Write-Fail "Unsupported Windows architecture: $rawArch (supported: amd64, arm64)."
                return
            }
        }
    }

    # Resolve non-admin user-level installation directory (never touches Program Files or HKLM).
    if ([string]::IsNullOrWhiteSpace($InstallDir)) {
        if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
            $InstallDir = Join-Path $env:LOCALAPPDATA 'Programs\peep'
        } else {
            $userHome = [Environment]::GetFolderPath('UserProfile')
            if ([string]::IsNullOrWhiteSpace($userHome)) { $userHome = $HOME }
            $InstallDir = Join-Path $userHome '.local\bin'
        }
    }
    $InstallDir = [System.IO.Path]::GetFullPath($InstallDir)

    Write-Host "Installing peep (user-scope, no admin required)..."
    Write-Host ""

    # Resolve latest version from GitHub Releases if not pinned.
    $iwrParams = @{ ErrorAction = 'Stop' }
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        $iwrParams['UseBasicParsing'] = $true
    }

    if ([string]::IsNullOrWhiteSpace($Version)) {
        try {
            $releaseApi = "https://api.github.com/repos/$Repo/releases/latest"
            $releaseResp = Invoke-RestMethod -Uri $releaseApi -Headers @{ 'User-Agent' = 'peep-installer' } -ErrorAction Stop
            $Version = $releaseResp.tag_name
        } catch {
            Write-Fail "Could not determine latest peep release from GitHub: $($_.Exception.Message)"
            Write-Info "Check your network/proxy settings or visit https://github.com/$Repo/releases"
            return
        }
    } elseif (-not $Version.StartsWith('v')) {
        $Version = "v$Version"
    }

    if ([string]::IsNullOrWhiteSpace($Version)) {
        Write-Fail "Could not resolve a release version tag."
        return
    }

    Write-Info "OS:          windows"
    Write-Info "Arch:        $Arch"
    Write-Info "Version:     $Version"
    Write-Info "Install dir: $InstallDir"
    Write-Host ""

    # Ensure target directory exists and is writable by the current non-admin user.
    try {
        if (-not (Test-Path -LiteralPath $InstallDir)) {
            New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
        }
        $probeFile = Join-Path $InstallDir ".peep-write-test-$PID"
        [System.IO.File]::WriteAllText($probeFile, '')
        Remove-Item -LiteralPath $probeFile -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Fail "Cannot write to '$InstallDir': $($_.Exception.Message)"
        Write-Info "Set a custom user-writable folder and re-run, for example:"
        Write-Info '  $env:PEEP_INSTALL_DIR = "$HOME\bin"'
        return
    }

    $BinaryName   = "peep-windows-$Arch.exe"
    $DownloadUrl  = "https://github.com/$Repo/releases/download/$Version/$BinaryName"
    $ChecksumsUrl = "https://github.com/$Repo/releases/download/$Version/checksums-sha256.txt"

    $TmpRoot = if ($env:TEMP) { $env:TEMP } else { [System.IO.Path]::GetTempPath() }
    $TmpDir  = Join-Path $TmpRoot ("peep-install-" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $TmpDir -Force | Out-Null

    try {
        $TmpBin       = Join-Path $TmpDir $BinaryName
        $TmpChecksums = Join-Path $TmpDir 'checksums-sha256.txt'

        Write-Host "Downloading $BinaryName..."
        try {
            Invoke-WebRequest -Uri $DownloadUrl -OutFile $TmpBin @iwrParams
        } catch {
            Write-Fail "Failed to download binary from $DownloadUrl"
            Write-Info $_.Exception.Message
            return
        }

        Write-Host "Downloading SHA-256 checksums..."
        try {
            Invoke-WebRequest -Uri $ChecksumsUrl -OutFile $TmpChecksums @iwrParams
        } catch {
            Write-Fail "Failed to download checksum file from $ChecksumsUrl"
            Write-Info "Aborting installation because SHA-256 integrity could not be verified."
            return
        }

        # Parse expected SHA-256 checksum for our exact binary.
        $ExpectedHash = $null
        foreach ($line in [System.IO.File]::ReadAllLines($TmpChecksums)) {
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
            $parts = $trimmed -split '\s+'
            if ($parts.Count -ge 2) {
                $fileField = $parts[$parts.Count - 1].TrimStart('*')
                if ($fileField -eq $BinaryName -or $fileField.EndsWith("/$BinaryName")) {
                    $ExpectedHash = $parts[0].ToLowerInvariant()
                    break
                }
            }
        }

        if ([string]::IsNullOrWhiteSpace($ExpectedHash)) {
            Write-Fail "No SHA-256 entry found for $BinaryName in checksums-sha256.txt."
            return
        }

        # Compute actual SHA-256 hash (Get-FileHash with .NET cryptography fallback for constrained policies).
        $ActualHash = $null
        if (Get-Command Get-FileHash -ErrorAction SilentlyContinue) {
            $ActualHash = (Get-FileHash -LiteralPath $TmpBin -Algorithm SHA256).Hash.ToLowerInvariant()
        } else {
            $sha256 = [System.Security.Cryptography.SHA256]::Create()
            try {
                $stream = [System.IO.File]::OpenRead($TmpBin)
                try {
                    $hashBytes = $sha256.ComputeHash($stream)
                    $ActualHash = ([BitConverter]::ToString($hashBytes) -replace '-', '').ToLowerInvariant()
                } finally {
                    $stream.Dispose()
                }
            } finally {
                $sha256.Dispose()
            }
        }

        if ($ActualHash -ne $ExpectedHash) {
            Write-Fail "SHA-256 checksum mismatch for $BinaryName!"
            Write-Info "Expected: $ExpectedHash"
            Write-Info "Got:      $ActualHash"
            return
        }
        Write-Ok "SHA-256 checksum verified ($ActualHash)"

        # Install to destination (handle locked running peep.exe safely via .old rename).
        $DestBin = Join-Path $InstallDir 'peep.exe'
        $OldBin  = Join-Path $InstallDir 'peep.exe.old'
        if (Test-Path -LiteralPath $OldBin) {
            Remove-Item -LiteralPath $OldBin -Force -ErrorAction SilentlyContinue
        }
        if (Test-Path -LiteralPath $DestBin) {
            try {
                Remove-Item -LiteralPath $DestBin -Force -ErrorAction Stop
            } catch {
                Move-Item -LiteralPath $DestBin -Destination $OldBin -Force
            }
        }

        Move-Item -LiteralPath $TmpBin -Destination $DestBin -Force

        # Clear Mark-of-the-Web (Zone.Identifier) best-effort so SmartScreen does not prompt non-admin users.
        try {
            if (Get-Command Unblock-File -ErrorAction SilentlyContinue) {
                Unblock-File -LiteralPath $DestBin -ErrorAction SilentlyContinue
            }
        } catch {
            # Non-fatal if alternate data streams are unsupported or restricted.
        }

        if (Test-Path -LiteralPath $OldBin) {
            Remove-Item -LiteralPath $OldBin -Force -ErrorAction SilentlyContinue
        }

        Write-Host ""
        Write-Ok "peep $Version installed to $DestBin"

        # Add $InstallDir to user-level PATH (HKCU:\Environment) and current session $env:Path.
        $skipPath = $NoModifyPath.IsPresent -or ($env:PEEP_NO_PATH -eq '1') -or ($env:PEEP_NO_PATH -eq 'true')
        if (-not $skipPath) {
            $normTarget = $InstallDir.TrimEnd('\')

            # 1. Update current PowerShell session immediately.
            $sessionEntries = ($env:Path -split ';') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            $inSession = $false
            foreach ($entry in $sessionEntries) {
                if ($entry.Trim().TrimEnd('\').Equals($normTarget, [StringComparison]::OrdinalIgnoreCase)) {
                    $inSession = $true
                    break
                }
            }
            if (-not $inSession) {
                $env:Path = if ([string]::IsNullOrWhiteSpace($env:Path)) { $InstallDir } else { "$InstallDir;$env:Path" }
            }

            # 2. Persist in User-scope PATH (never Machine scope -- safe for standard non-admin accounts).
            try {
                $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
                $userEntries = @()
                if (-not [string]::IsNullOrWhiteSpace($userPath)) {
                    $userEntries = ($userPath -split ';') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
                }

                $inUserPath = $false
                foreach ($entry in $userEntries) {
                    if ($entry.Trim().TrimEnd('\').Equals($normTarget, [StringComparison]::OrdinalIgnoreCase)) {
                        $inUserPath = $true
                        break
                    }
                }

                if (-not $inUserPath) {
                    $newUserPath = if ($userEntries.Count -eq 0) {
                        $InstallDir
                    } else {
                        ($userEntries + $InstallDir) -join ';'
                    }
                    [Environment]::SetEnvironmentVariable('Path', $newUserPath, 'User')
                    Write-Ok "Added '$InstallDir' to your user PATH (new terminals will pick it up automatically)"
                } else {
                    Write-Info "User PATH already contains '$InstallDir'"
                }
            } catch {
                Write-Warn "Could not persist user PATH in registry (restricted by policy): $($_.Exception.Message)"
                Write-Info "peep is active in this PowerShell window. To persist it via your PowerShell profile, run:"
                Write-Info "  Add-Content -Path `$PROFILE -Value '`$env:Path = `"$InstallDir;`$env:Path`"'"
            }
        }

        Write-Host ""
        Write-Host "Get started:"
        Write-Info "peep google.com"
        Write-Info "peep --examples"
        Write-Info "peep --help"
    } finally {
        if (Test-Path -LiteralPath $TmpDir) {
            Remove-Item -LiteralPath $TmpDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Install-Peep @args
