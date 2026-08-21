# Changelog

All notable changes to peep will be documented in this file.

## [0.7.0] — 2025-08-21

### Added
- **Connectivity check** (`-c` / `--connect` / `--knock`) — TCP-only reachability test, like telnet or netcat but with peep's diagnostics. Supports JSON output.
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
