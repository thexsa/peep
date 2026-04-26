# 👀 peep — TLS diagnostics in plain English

**Stop memorizing openssl flags.** peep tells you what's wrong with a certificate or connection — in plain English, not hex dumps.

Built for **support engineers**, sysadmins, and anyone who's ever Googled _"openssl check certificate command"_ for the 47th time.

```
$ peep self-signed.badssl.com
┃    Peeping at self-signed.badssl.com:443
┃    IP: 104.154.89.105
┃    Protocol: Direct TLS
┃    Direct TLS handshake completed successfully
┃
┃    ⚠ SERVER DID NOT INCLUDE THE ISSUING CA IN ITS RESPONSE
┃      One job. You had ONE job. Bundle the certs correctly. ONE. JOB.
┃
┃    Verdict: Appears to be Written in Crayon
┃    If this cert were a building, it would've been condemned.
┃
┃    Findings: 3 issue(s) detected
┃      [WARN] Self-Signed Certificate
┃      [FAIL] No Issuing CA in Server Response
┃      [FAIL] Chain Verification Failed
┃
┃    [PASS] TLS: TLSv1.2
┃    [PASS] Cipher: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
┃  CHAIN OF TRUST
┃
┃  [WARN] Leaf *.badssl.com
┃    Expires: 725 days (Apr 20, 2028)
┃    Covers: *.badssl.com, badssl.com
┃    Key: RSA
┃    Serial: EC7256235A58C012
┃    SHA-256: 3F2A:DC71:E756:...
┃    Self-signed!
┃
┃  [FAIL] No Issuing CA in server response
┃         The chain has exactly one link. That's not a chain. That's a pendant.
┃
┃  [FAIL] Trust store verification failed
┃         x509: certificate signed by unknown authority
┃         Trust store says no. Browsers say no. I say no. Everybody says no.
```

---

## Features

### 🔍 Smart Protocol Detection
Just give peep a host and port. It figures out the rest.

| Port | Protocol | What peep does |
|------|----------|----------------|
| 443 | HTTPS | Direct TLS handshake |
| 587/25 | SMTP | STARTTLS upgrade |
| 3389 | RDP | X.224 negotiation → TLS _(where openssl fails!)_ |
| 636 | LDAPS | Direct TLS |
| 389 | LDAP | STARTTLS extended operation |
| 993/995 | IMAPS/POP3S | Direct TLS |
| 21 | FTP | AUTH TLS upgrade |

Override with `-p`/`--proto` when services run on non-standard ports:
```bash
peep -p smtp mailserver:2525
```

### 🔗 Chain of Trust Visualization
See exactly who signed what, whether the chain is complete, and what role each cert plays — with serial numbers and SHA-256 fingerprints.

### 📖 `--explain` Mode
Don't just show the problem — explain it, recommend a fix, and link to the relevant built-in docs:
```bash
$ peep --explain example.com

┃  [FAIL] No Issuing CA in Server Response
┃       The server did not include the issuing CA certificate ...
┃
┃       Why this matters:
┃       During the TLS handshake, the server is expected to send the
┃       complete certificate chain ...
┃
┃       Recommended fix:
┃       Add the issuing CA (intermediate) certificate to the server's
┃       cert chain. Concatenate them: cat leaf.crt intermediate.crt > fullchain.crt ...
┃
┃       📖 Learn more:  peep docs chain
```

### 📚 Built-in TLS Reference
Learn TLS concepts without leaving the terminal:
```bash
peep docs                  # Table of contents
peep docs tls              # What is TLS?
peep docs certs            # Leaf vs Intermediate vs Root
peep docs chain            # How chain of trust works
peep docs ciphers          # Cipher suites explained
peep docs tls-handshake    # TLS 1.2 vs 1.3 handshake flows
peep docs starttls         # What STARTTLS is
peep docs rdp              # Why RDP certs are special
peep docs troubleshooting  # Common issues checklist
```

### 📊 JSON Output
Pipe to `jq`, feed into monitoring, or parse in CI/CD:
```bash
peep --json example.com | jq '.overall_status'
peep --json --explain example.com | jq '.warnings[].fix'
```

### 🌶️ Sarcastic Commentary
Every finding comes with rotating sarcastic remarks. Because debugging TLS should at least be entertaining.

---

## Installation

### Option 1: Download a binary

Grab the latest binary for your platform from the [Releases](https://github.com/thexsa/peep/releases) page.

| Platform | Binary |
|----------|--------|
| macOS (Apple Silicon) | `peep-darwin-arm64` |
| macOS (Intel) | `peep-darwin-amd64` |
| Linux (x86_64) | `peep-linux-amd64` |
| Linux (ARM64) | `peep-linux-arm64` |
| Linux (ppc64le) | `peep-linux-ppc64le` |
| Windows (x86_64) | `peep-windows-amd64.exe` |

#### Make it executable and add to your PATH

**macOS / Linux:**
```bash
# Download (example for macOS ARM)
curl -LO https://github.com/thexsa/peep/releases/latest/download/peep-darwin-arm64

# Make it executable
chmod +x peep-darwin-arm64

# Move to a directory in your PATH
sudo mv peep-darwin-arm64 /usr/local/bin/peep

# Verify
peep --help
```

**Windows:**

Download `peep-windows-amd64.exe`, rename it to `peep.exe`, and place it in a directory that's in your `%PATH%` (e.g., `C:\Users\<you>\bin`).

### Option 2: Build from source

Requires **Go 1.23+**. No CGO, no OpenSSL, no external dependencies.

```bash
git clone https://github.com/thexsa/peep.git
cd peep

# Build for your current platform
make build

# The binary is at ./peep — run it directly:
./peep google.com

# Or move it to your PATH:
sudo mv peep /usr/local/bin/peep
```

#### Cross-compile for all platforms
```bash
make build-all
# Outputs to dist/:
#   dist/peep-darwin-arm64
#   dist/peep-linux-amd64
#   dist/peep-linux-ppc64le
#   dist/peep-windows-amd64.exe
```

---

## Usage

```bash
# Quick check (defaults to port 443)
peep example.com

# Specific port (always host:port format)
peep example.com:8443

# Extra cert details (subject, issuer, key info, SANs, etc.)
peep -v example.com

# Full details + base64 PEM certs
peep -vv example.com
# or:
peep --verbose example.com

# Explain every issue with fixes and doc references
peep --explain example.com

# JSON output (for scripting / CI/CD)
peep --json example.com
peep --json --explain -vv example.com

# SMTP (auto-detects STARTTLS)
peep mail.example.com:587

# RDP (handles X.224 negotiation)
peep rdp-server.example.com:3389

# Force protocol on non-standard port
peep -p smtp mailrelay.internal:2525

# Plain text output (no color, no emoji — easy to copy/paste)
peep --plain-text example.com

# Deep scan (cipher enumeration, OCSP, CT logs)
peep scan example.com

# Skip trust store verification (for self-signed certs)
peep --insecure internal-server.local:443

# Built-in docs
peep docs certs
```

### All Flags
| Flag | Short | Description |
|------|-------|-------------|
| `--proto` | `-p` | Force protocol: `tls`, `smtp`, `rdp`, `ldap`, `ftp` |
| `--explain` | | Explain each issue with fix recommendations and doc references |
| `-v` | | Extra cert details (subject, issuer, key info, SANs) |
| `-vv` / `--verbose` | | Max verbosity — includes base64 PEM certs |
| `--json` | | JSON output for scripting (respects -v, -vv, --explain) |
| `--plain-text` | | No color, no emoji, no Unicode — easy to copy/paste |
| `--timeout` | `-t` | Connection timeout in seconds (default: 5) |
| `--insecure` | | Skip system trust store verification |

Port is always specified in the host argument: `host:port` (default: 443)

### Flag Combinations
Flags work in any order and combine freely:
```bash
peep --json --explain -vv example.com    # Full JSON with explanations and PEM certs
peep -v --json example.com              # JSON with extra cert details
peep --explain example.com              # CLI with issue explanations
peep --plain-text --explain example.com  # Copy/paste friendly with explanations
```

---

## Shell Autocompletion

peep supports tab-completion for bash, zsh, fish, and PowerShell. This is optional — peep works fine without it.

Autocompletion lets you tab-complete commands and flags:
```
peep do<TAB>     →  peep docs
peep --ex<TAB>   →  peep --explain
```

#### Setup (one-time)

**Zsh** (macOS default):
```bash
# Add to your ~/.zshrc:
source <(peep completion zsh)

# Or install permanently:
peep completion zsh > "${fpath[1]}/_peep"
```

**Bash:**
```bash
# Current session:
source <(peep completion bash)

# Permanent (Linux):
peep completion bash > /etc/bash_completion.d/peep

# Permanent (macOS with bash-completion):
peep completion bash > $(brew --prefix)/etc/bash_completion.d/peep
```

**Fish:**
```bash
peep completion fish > ~/.config/fish/completions/peep.fish
```

**PowerShell:**
```powershell
peep completion powershell | Out-String | Invoke-Expression
```

> **Note:** Autocompletion requires `peep` to be in your `$PATH` (not just `./peep`). See the [Installation](#installation) section.

---

## Why Not Just Use OpenSSL?

| Task | openssl | peep |
|------|---------|------|
| Check a cert | `openssl s_client -connect host:443 -servername host < /dev/null 2>/dev/null \| openssl x509 -noout -dates` | `peep host` |
| Check SMTP cert | `openssl s_client -connect host:587 -starttls smtp` | `peep host:587` |
| Check RDP cert | ❌ _Can't_ | `peep host:3389` |
| See the chain | `openssl s_client -connect host:443 -showcerts` | `peep host` |
| Understand what's wrong | _Read the hex and figure it out_ | _peep tells you in English_ |
| Get fix recommendations | ❌ _Nope_ | `peep --explain host` |
| JSON for CI/CD | _Roll your own parser_ | `peep --json host` |

---

## Technical Details

- **100% Go** — no CGO, no OpenSSL, no external runtime dependencies
- **Single binary** — download and run, nothing to install
- **Cross-platform** — macOS (ARM), Linux (amd64, ppc64le), Windows (amd64)
- **CLI framework** — [spf13/cobra](https://github.com/spf13/cobra) (Apache 2.0)
- **Terminal styling** — [charmbracelet/lipgloss](https://github.com/charmbracelet/lipgloss) (MIT)
- **Terminal width** — [golang.org/x/term](https://pkg.go.dev/golang.org/x/term) (BSD-3-Clause)

---

## License

Apache 2.0 — see [LICENSE](LICENSE) for the full text.

---

_Built with Go — no OpenSSL required._
