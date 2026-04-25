# 👀 peep — Your Digital Eyes for TLS

**Stop memorizing openssl flags.** peep is a TLS diagnostic tool that tells you what's wrong with a certificate or connection — in plain English, not hex dumps.

Built for **L1/L2 support engineers**, sysadmins, and anyone who's ever Googled _"openssl check certificate command"_ for the 47th time.

```
$ peep example.com
╭──────────────────────────────────────────────╮
│  👀 peep — your digital eyes for TLS         │
│     Peeping at: example.com:443              │
│     IP: 93.184.216.34                        │
│     Protocol: Direct TLS                     │
╰──────────────────────────────────────────────╯

╭──────────────────────────────────────────────╮
│ 🤝 TLS Handshake                             │
│ TLS Version:  TLSv1.3  ✅ Clear Skies       │
│ Cipher Suite: TLS_AES_256_GCM_SHA384  ✅    │
╰──────────────────────────────────────────────╯

╭──────────────────────────────────────────────╮
│ 🔗 Chain of Trust                            │
│                                              │
│ 🏛️  Root CA (DigiCert Global Root G2)       │
│ │   Status: ✅ Trusted                       │
│ │                                            │
│ ├── 📋 Intermediate (DigiCert SHA2 EV CA)   │
│ │   Status: ✅ Valid                          │
│ │                                            │
│ └── 📄 Leaf (*.example.com)                  │
│     Status: ✅ Valid, 342 days left           │
│     Covers: *.example.com, example.com       │
╰──────────────────────────────────────────────╯

╭──────────────────────────────────────────────╮
│ Overall Assessment                           │
│ ✅ Clear Skies                               │
│ Everything's looking good. Go grab a coffee. │
╰──────────────────────────────────────────────╯
```

---

## Who Is This For?

**You**, if you've ever:
- 🤔 Wondered _"why isn't this cert working?"_ but couldn't figure out the right openssl incantation
- 😤 Tried to check an RDP cert and got nothing because `openssl s_client` doesn't speak X.224
- 🤷 Been told to _"check the certificate chain"_ but didn't know what a chain was
- 📞 Spent 30 minutes on a support call trying to explain what "missing intermediate" means

peep gives you **clear, color-coded diagnostics** with plain-English explanations. No cryptography PhD required.

---

## Features

### 🔍 Smart Protocol Detection
Just give peep a host and port. It figures out the rest.

| Port | Protocol | What peep does |
|------|----------|----------------|
| 443 | HTTPS | Direct TLS handshake |
| 587/25 | SMTP | STARTTLS upgrade automatically |
| 3389 | RDP | X.224 negotiation → TLS _(where openssl fails!)_ |
| 636 | LDAPS | Direct TLS |
| 389 | LDAP | STARTTLS extended operation |
| 993/995 | IMAPS/POP3S | Direct TLS |

Override with `--proto` when services run on non-standard ports:
```bash
peep --proto smtp mailserver:2525
```

### 🔗 Visual Chain of Trust
See exactly who signed what, whether the chain is complete, and what role each certificate plays:
- **📄 Leaf** — the server's identity cert
- **📋 Intermediate (Issuing CA)** — the notary that vouches for the leaf
- **🏛️ Root CA** — the ultimate authority in your trust store

### ✅ ⚠️ ❌ Weather Report Status
Every finding gets a clear status:
- **✅ Clear Skies** — everything looks good
- **⚠️ Cloudy** — not broken, but needs attention
- **❌ Stormy** — critical issue, fix immediately

### 💡 `--why` Explanations
Don't just show the problem — explain it:
```bash
$ peep --why example.com

❌ Missing Intermediate Certificate
   💡 The server forgot to send an intermediate cert. It's like mailing
      a letter with no return address and wondering why nobody writes back.
```

### 🌶️ `--rude` Mode
For when you want brutally honest diagnostics:
```bash
$ peep --rude example.com

❌ Missing Intermediate Certificate
   💡 You forgot the intermediate cert. The ENTIRE chain of trust is broken.
      Half the browsers on earth can't verify this cert. How did this pass
      testing? DID you test?
```

### 📚 Built-in Documentation
Learn TLS concepts without leaving the terminal:
```bash
peep docs              # Table of contents
peep docs tls          # What is TLS?
peep docs certs        # Leaf vs Intermediate vs Root
peep docs chain        # How chain of trust works
peep docs ciphers      # Cipher suites explained
peep docs starttls     # What STARTTLS is
peep docs rdp          # Why RDP certs are special
peep docs troubleshooting  # Common issues checklist
```

---

## Installation

### Download Binary
Grab the latest release for your platform from the [releases page](#).

| Platform | Binary |
|----------|--------|
| macOS (Apple Silicon) | `peep-darwin-arm64` |
| Linux (x86_64) | `peep-linux-amd64` |
| Linux (ppc64le) | `peep-linux-ppc64le` |
| Windows (x86_64) | `peep-windows-amd64.exe` |

### Build from Source
```bash
git clone https://github.com/peep-tls/peep.git
cd peep
make build        # Build for your current platform
make build-all    # Cross-compile for all platforms
```

Requires Go 1.23+. No CGO, no OpenSSL dependency. Pure Go.

---

## Usage

```bash
# Basic check (defaults to port 443)
peep example.com

# Specific port
peep example.com:8443

# SMTP (auto-detects STARTTLS)
peep mail.example.com:587

# RDP (auto-handles X.224 negotiation)
peep rdp-server.example.com:3389

# Force protocol on non-standard port
peep --proto smtp mailrelay.internal:2525

# Show educational explanations
peep --why example.com

# Brutally honest mode
peep --rude example.com

# Focus on chain only
peep chain example.com

# Built-in docs
peep docs certs

# Skip trust store verification (for self-signed certs)
peep --insecure internal-server.local:443
```

### All Flags
| Flag | Short | Description |
|------|-------|-------------|
| `--port` | `-p` | Override port |
| `--proto` | | Force protocol: `tls`, `smtp`, `rdp`, `ldap` |
| `--why` | | Show plain-English explanations for warnings |
| `--rude` | | Enable brutally honest mode 🌶️ |
| `--timeout` | `-t` | Connection timeout in seconds (default: 5) |
| `--insecure` | | Skip system trust store verification |
| `--no-color` | | Disable color output |
| `--json` | | JSON output (planned) |

---

## Why Not Just Use OpenSSL?

| Task | openssl | peep |
|------|---------|------|
| Check a cert | `openssl s_client -connect host:443 -servername host < /dev/null 2>/dev/null \| openssl x509 -noout -dates` | `peep host` |
| Check SMTP cert | `openssl s_client -connect host:587 -starttls smtp` | `peep host:587` |
| Check RDP cert | ❌ _Can't do it_ | `peep host:3389` |
| See the chain | `openssl s_client -connect host:443 -showcerts` | `peep chain host` |
| Understand what's wrong | _You read the hex and figure it out_ | _peep tells you in plain English_ |

---

## Technical Details

- **100% Go** — no CGO, no OpenSSL, no external dependencies
- **Cross-platform** — darwin/arm64, linux/amd64, linux/ppc64le, windows/amd64
- **Single binary** — download and run, no installation required
- **CLI Framework** — [spf13/cobra](https://github.com/spf13/cobra)
- **Terminal UI** — [charmbracelet/lipgloss](https://github.com/charmbracelet/lipgloss)

---

## License

MIT

---

_Built with ❤️ and pure Go — no OpenSSL required._
