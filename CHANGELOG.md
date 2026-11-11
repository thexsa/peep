# Changelog

All notable changes to peep will be documented in this file.

## [0.8.0] — 2026-11-10

### Added
- **Deterministic Missing-SAN & CN-Only Fallback Detection** (`CERT_MISSING_SANS`, `CERT_CN_ONLY`) — leaf certificates without DNS/IP Subject Alternative Names or relying on deprecated `CommonName` fallback are now flagged deterministically across all OSes (including Windows) and all commands/flags (`peep`, `peep scan`, `peep find-certs`, `-i`, `--internal-ca`, `--ca-bundle`, `-j`), with 28 dedicated sarcastic remarks.
- **Cross-OS Wire-Complete Chain & `SSL_CERT_FILE` / `SSL_CERT_DIR` Parity** — detects omitted intermediates even on multi-cert chains when macOS `SecTrust` or Windows `CryptoAPI` silently resolves missing intermediates via AIA or OS cache, honors `SSL_CERT_FILE` and `SSL_CERT_DIR` across all platforms (including macOS and Windows), and adds AIX `/opt/freeware/etc/ssl/certs/ca-bundle.crt` fallback.
- **Windows Non-Admin PowerShell Installer (`install.ps1`) & `windows/arm64` Builds** — supports native `amd64` and `arm64` Windows binaries, SHA-256 checksum verification, and user-level `%LOCALAPPDATA%\Programs\peep` + user `PATH` setup with zero Administrator/UAC privileges required; `install.sh` now also supports IBM AIX (`ppc64`).
- **Protocol-Aware Cipher Enumeration & Full IPv6 Target Parsing** — `peep scan` now enumerates TLS versions and cipher suites across all 11 protocols (STARTTLS, RDP X.224, PostgreSQL, MySQL, MSSQL, LDAP, FTP, IMAP, POP3, XMPP, and Direct TLS), honors `-v`/`--verbose` PEM + raw X.509 output, and supports bracketed and bare IPv6 targets across all commands.
- **Windows AD CS CRL Hint** — `peep scan` now renders both Unix `ldapsearch` and Windows `certutil -URL` commands for Active Directory `ldap://` CRL distribution points.

### Changed
- **Strict 7-bit ASCII & Zero-Emoji Guarantee for `-p` / `--plain-text` / `--shades`** — maps all verdicts (`[Browser]`, `[Service]`, `->`, `[OK]`, `[FAIL]`, `--`, `...`), strips ANSI CSI codes, suppresses `\r` progress spinners on non-TTY/plain-text streams, and enforces clean 7-bit ASCII across every command and output block.
- **Cross-OS Shell Autocompletion & Self-Update Hardening** — `peep completion --install` now detects Git Bash/MSYS2/Cygwin on Windows, `pwsh` on macOS/Linux, macOS `.bash_profile`, and AIX `ksh`; `peep update` cleans up leftover `.old` binaries on Windows and executes the newly installed binary path reliably across Windows, Linux, macOS, and AIX.
- **Port Scanner & Discovery Socket Resilience** — `portscan` and `find-certs` automatically tune `RLIMIT_NOFILE` on Unix (macOS, Linux, AIX, FreeBSD) and retry transient ephemeral socket exhaustion errors.

### Removed
- Removed deprecated hidden flag aliases `--lens`, `--gaze`, and `--knock` (base flags `-P`/`--proto`, `-d`/`--details`, and `-c`/`--connect` remain unchanged).

## [0.7.0] — 2025-08-21

### Added
- **Connectivity check** (`-c` / `--connect`) — TCP-only reachability test, like telnet or netcat but with peep's diagnostics. Supports JSON output.
- **Port scanning** (`peep portscan`) — TCP connect scan for discovering open ports. Normal mode scans the top 50 service ports; `--full` scans all 65,535 ports.
- **Certificate discovery** (`peep find-certs` / `find-cert`) — protocol-aware certificate scanning across ports. Uses correct handshake per port (STARTTLS, X.224, TDS, SSLRequest, etc.).
- **6 new protocol probes** — POP3 (STLS), IMAP (STARTTLS), MSSQL (TDS PreLogin TLS), MySQL (SSL negotiation), PostgreSQL (SSLRequest), and XMPP (STARTTLS).
- **System CA store path** — now displayed after chain verification in both pass and fail cases, showing which trust store was used.
- **Post-update "What's New"** — after updating, peep now shows a brief summary of what changed in the new version.

### Changed
- Smart Protocol Detection now supports 11 protocols (up from 5).
- Trust verification failure output now includes snarky remarks that reference the CA store path.

## [0.6.0] — 2025-07-15

### Added
- Dual-verdict system (Browser vs Service/API grading)
- Private CA auto-detection with confidence scoring
- OCSP Must-Staple support
- `--internal-ca` flag for internal/private CA grading adjustments
- `--ca-bundle` flag for custom CA trust store
