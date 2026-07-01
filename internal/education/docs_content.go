package education

import (
	"fmt"
	"strings"
)

// Topic represents a built-in documentation topic.
type Topic struct {
	Name     string
	Title    string
	Summary  string
	Content  string
}

// GetTopics returns all available documentation topics.
func GetTopics() []Topic {
	return []Topic{
		topicTLS(),
		topicTLSHandshake(),
		topicCerts(),
		topicChain(),
		topicCiphers(),
		topicCRL(),
		topicOCSP(),
		topicAIA(),
		topicStartTLS(),
		topicRDP(),
		topicTroubleshooting(),
	}
}

// GetTopic returns a single topic by name, or nil if not found.
func GetTopic(name string) *Topic {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, t := range GetTopics() {
		if t.Name == name {
			return &t
		}
	}
	return nil
}

// TableOfContents returns a formatted table of contents.
func TableOfContents() string {
	var sb strings.Builder
	sb.WriteString("📚 peep docs — Built-in TLS Reference Guide\n\n")
	sb.WriteString("Available topics:\n\n")
	for _, t := range GetTopics() {
		sb.WriteString(fmt.Sprintf("  %-20s %s\n", t.Name, t.Summary))
	}
	sb.WriteString("\nUsage: peep docs <topic>\n")
	sb.WriteString("Example: peep docs tls\n")
	return sb.String()
}

func topicTLS() Topic {
	return Topic{
		Name:    "tls",
		Title:   "TLS — Transport Layer Security",
		Summary: "What is TLS? Version history and why versions matter.",
		Content: `
🔒 TLS — Transport Layer Security
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

TLS is the protocol that puts the "S" in "HTTPS." It encrypts the data
between your browser (or any client) and a server so nobody in between
can read or tamper with it.

📖 QUICK HISTORY:
  • SSL 2.0 (1995) — Broken. Never use.
  • SSL 3.0 (1996) — Also broken (POODLE attack). Never use.
  • TLS 1.0 (1999) — Deprecated 2021. Has known vulnerabilities.
  • TLS 1.1 (2006) — Deprecated 2021. Slightly better, still bad.
  • TLS 1.2 (2008) — Still good! Most of the Internet runs on this.
  • TLS 1.3 (2018) — The best. Faster handshakes, stronger security.

🎯 WHAT YOU NEED TO KNOW:
  1. If you see TLS 1.0 or 1.1 → That's a problem. Upgrade ASAP.
  2. TLS 1.2 is fine as long as the cipher suite is strong.
  3. TLS 1.3 is the gold standard. Aim for this.

⚡ TLS 1.2 vs TLS 1.3 — KEY DIFFERENCES:
  • TLS 1.2: 2 round-trips to complete handshake (slower)
    TLS 1.3: 1 round-trip (faster), supports 0-RTT resumption
  • TLS 1.2: Cipher suite negotiation includes key exchange + auth + cipher
    TLS 1.3: Only 5 cipher suites, all secure by design — no bad choices
  • TLS 1.2: Supports RSA key exchange (no Forward Secrecy)
    TLS 1.3: REQUIRES ephemeral key exchange (always Forward Secrecy)
  • TLS 1.2: Server cert sent in plaintext during handshake
    TLS 1.3: Server cert is encrypted during handshake (more privacy)
  See: peep docs tls-handshake for the full handshake flow diagrams.

🌐 HTTP/1.1 vs HTTP/2 — HOW TLS IS AFFECTED:
  • HTTP/1.1: One request per TCP connection (or pipelining, rarely used)
    HTTP/2:   Multiplexed — many requests over a single TLS connection
  • HTTP/2 practically requires TLS (all major browsers enforce it)
  • HTTP/2 uses ALPN (Application-Layer Protocol Negotiation) during the
    TLS handshake to agree on "h2" (HTTP/2) vs "http/1.1"
  • HTTP/2 has a cipher suite blacklist — some ciphers valid in TLS 1.2
    are rejected by HTTP/2 (e.g., AES-CBC based suites)
  • HTTP/3 uses QUIC (UDP-based), which has TLS 1.3 built in

💡 FUN FACT:
  "SSL" and "TLS" are often used interchangeably, but SSL is technically
  dead. When someone says "SSL certificate," they mean a certificate used
  with TLS. It's like calling every tissue a "Kleenex."
`,
	}
}

func topicTLSHandshake() Topic {
	return Topic{
		Name:    "tls-handshake",
		Title:   "TLS Handshake — How Connections Are Established",
		Summary: "TLS 1.2 vs 1.3 handshake flows, ALPN, and 0-RTT.",
		Content: `
🤝 TLS Handshake — How Connections Are Established
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

The TLS handshake is the process where a client and server agree on
how to encrypt their conversation. It happens before any application
data (like HTTP requests) can be sent.

──────────────────────────────────────────────────────
📋 TLS 1.2 HANDSHAKE (2 Round-Trips)
──────────────────────────────────────────────────────

  Client                              Server
    │                                    │
    │──── ClientHello ──────────────────>│  Round-trip 1
    │     (supported ciphers,            │
    │      supported TLS versions,       │
    │      random bytes,                 │
    │      ALPN: [h2, http/1.1])         │
    │                                    │
    │<─── ServerHello ──────────────────│
    │     (chosen cipher,                │
    │      chosen TLS version,           │
    │      random bytes,                 │
    │      ALPN: h2)                     │
    │<─── Certificate ──────────────────│  ⚠️  Sent in PLAINTEXT!
    │     (server cert chain)            │
    │<─── ServerKeyExchange ────────────│  (if using ECDHE)
    │<─── ServerHelloDone ──────────────│
    │                                    │
    │──── ClientKeyExchange ────────────>│  Round-trip 2
    │──── ChangeCipherSpec ─────────────>│
    │──── Finished ─────────────────────>│
    │                                    │
    │<─── ChangeCipherSpec ─────────────│
    │<─── Finished ─────────────────────│
    │                                    │
    │═══════ ENCRYPTED DATA ═══════════│  🔒 Now encrypted!

  Total: 2 round-trips before first byte of data
  ⚠️  The server certificate is visible to anyone watching the network
  ⚠️  If RSA key exchange is used (no ECDHE), no Forward Secrecy

──────────────────────────────────────────────────────
⚡ TLS 1.3 HANDSHAKE (1 Round-Trip)
──────────────────────────────────────────────────────

  Client                              Server
    │                                    │
    │──── ClientHello ──────────────────>│  Single round-trip!
    │     (supported ciphers,            │
    │      key_share: [ECDHE params],    │
    │      supported_versions: [1.3],    │
    │      ALPN: [h2, http/1.1])         │
    │                                    │
    │<─── ServerHello ──────────────────│
    │     (chosen cipher,                │
    │      key_share: [ECDHE params])    │
    │<─── {EncryptedExtensions} ────────│  🔒 Everything below is encrypted!
    │<─── {Certificate} ────────────────│  🔒 Cert is ENCRYPTED (not visible)
    │<─── {CertificateVerify} ──────────│  🔒
    │<─── {Finished} ──────────────────│  🔒
    │                                    │
    │──── {Finished} ──────────────────>│  🔒
    │                                    │
    │═══════ ENCRYPTED DATA ═══════════│  🔒 Ready!

  Total: 1 round-trip before first byte of data
  ✅ Server certificate is ENCRYPTED (privacy improvement)
  ✅ Forward Secrecy is ALWAYS on (ECDHE is mandatory)
  ✅ Fewer messages, fewer options, fewer things to go wrong

──────────────────────────────────────────────────────
🚀 TLS 1.3 — 0-RTT RESUMPTION (Zero Round-Trips)
──────────────────────────────────────────────────────

  If the client has connected to this server before, TLS 1.3 can send
  application data IMMEDIATELY — zero round-trips:

  Client                              Server
    │                                    │
    │──── ClientHello ──────────────────>│  0 round-trips!
    │     + early_data (0-RTT)           │
    │     (encrypted with previous       │
    │      session key)                  │
    │                                    │
    │<─── ServerHello + data ───────────│
    │                                    │
    │═══════ ENCRYPTED DATA ═══════════│

  ⚠️  0-RTT data is NOT replay-protected! An attacker could capture and
      resend it. Only safe for idempotent requests (GET, not POST).
  💡 Most servers disable 0-RTT by default for this reason.

──────────────────────────────────────────────────────
🌐 ALPN — Application-Layer Protocol Negotiation
──────────────────────────────────────────────────────

  ALPN happens INSIDE the TLS handshake. It's how the client and server
  agree on which application protocol to use BEFORE sending any data.

  Common ALPN values:
    • "h2"        → HTTP/2
    • "http/1.1"  → HTTP/1.1
    • "h3"        → HTTP/3 (over QUIC)

  Why it matters:
    • HTTP/2 REQUIRES ALPN. If the server doesn't advertise "h2",
      the client falls back to HTTP/1.1.
    • This is why HTTP/2 effectively requires TLS — ALPN only exists
      inside the TLS handshake.
    • If you see HTTP/1.1 when you expected HTTP/2, check if the server's
      TLS config advertises ALPN "h2".

──────────────────────────────────────────────────────
📊 SIDE-BY-SIDE SUMMARY
──────────────────────────────────────────────────────

  Feature              TLS 1.2           TLS 1.3
  ─────────────────    ────────────────  ────────────────
  Round-trips          2                 1 (or 0 with 0-RTT)
  Forward Secrecy      Optional          Always (mandatory)
  Cert visibility      Plaintext         Encrypted
  Cipher suites        300+ choices      5 choices (all good)
  0-RTT resumption     No                Yes (with caveats)
  RSA key exchange     Allowed           Removed
  CBC ciphers          Allowed           Removed
  ChangeCipherSpec     Required          Removed
  Session tickets      Optional          Built-in (PSK)
`,
	}
}

func topicCerts() Topic {
	return Topic{
		Name:    "certs",
		Title:   "Certificates — Leaf, Intermediate, and Root",
		Summary: "Types of certificates and what each one does.",
		Content: `
📜 Certificates — The Chain of Trust
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Think of certificates like a chain of vouching:

📄 LEAF CERTIFICATE (aka "End-Entity" or "Server Certificate")
  • This is the cert installed on the server.
  • It proves "I am example.com."
  • It CANNOT sign other certificates.
  • It's the one your browser checks first.
  • ⚡ This is the cert that expires and needs renewal.

📋 INTERMEDIATE CERTIFICATE (aka "Issuing CA")
  • This cert signed the leaf cert — it's the notary.
  • The server MUST send this along with the leaf cert.
  • If it's missing, many clients will show an error.
  • 💡 When someone says "Add the Issuing cert", "The Issuing cert is missing",
       or "Make sure you send the Issuing cert with the Leaf" they mean this one.
  • There can be multiple intermediates in a chain.

🏛️  ROOT CERTIFICATE (aka "Root CA" or "Trust Anchor")
  • The ultimate authority — the top of the trust chain.
  • This cert lives in your OS/browser's trust store.
  • The server should NOT send this — the client already has it.
  • Root CAs are distributed by organizations like DigiCert, Let's Encrypt, Sectigo, etc.
  • 💡 Your organization may also have its own Root CA (internal/private PKI).
       If so, that Root CA cert must be installed on all corporate devices
       (laptops, servers, phones) for internal services to be trusted.

🎯 COMMON MISTAKES:
  1. Forgetting to install the intermediate cert → broken chain!
  2. Installing the root cert on the server → unnecessary, wastes bandwidth.
  3. Confusing which cert goes where → the leaf goes on the server,
     the intermediate goes WITH the leaf, the root stays in the trust store.
`,
	}
}

func topicChain() Topic {
	return Topic{
		Name:    "chain",
		Title:   "Chain of Trust — How Certificate Chains Work",
		Summary: "How chain of trust works, and common chain problems.",
		Content: `
🔗 Chain of Trust
━━━━━━━━━━━━━━━━━━━

The chain of trust is how a browser or other application decides to trust a certificate:

  🏛️  Root CA (DigiCert)         ← Already in your trust store
   │
   └──📋 Intermediate CA         ← Server must send this!
       │
       └──📄 Leaf Cert            ← Installed on the server
           (*.example.com)

The browser or other application checks:
  1. Does the leaf cert cover the hostname I'm connecting to?
  2. Was the leaf cert signed by the intermediate?
  3. Was the intermediate signed by a root I trust?

If any link in this chain is broken → 🔴 CONNECTION REFUSED.

🚨 COMMON CHAIN PROBLEMS:

  ❌ Missing Intermediate:
     The server only sends the leaf cert. Some browsers or applications can
     "fill in the gap" by fetching intermediates, but many clients can't.
     Fix: Install the intermediate cert alongside the leaf cert.

  ❌ Wrong Order:
     Certs should be sent: leaf → intermediate → (optional root).
     If they're shuffled, some TLS libraries get confused.
     Fix: Concatenate cert files in the correct order.

  ❌ Wrong Intermediate:
     The server sends an intermediate that didn't actually sign the leaf.
     This usually happens after a CA reissues their intermediate.
     Fix: Download the correct intermediate from your CA's website.

  ⚠️  Unnecessary Root:
     The server sends the root CA cert. Not harmful, but pointless —
     the client already has it. Just wastes bandwidth.

──────────────────────────────────────────────────────
📦 CHAIN COMPOSITION — WHAT THE SERVER SHOULD SEND
──────────────────────────────────────────────────────

  What the server sends       Verdict       Why
  ─────────────────────────   ───────────   ─────────────────────────────────
  Leaf only                   ❌ BROKEN      No chain — clients can't verify
  Leaf + Intermediate(s)      ✅ OPTIMAL     Gold standard — this is correct
  Leaf + Root (no inter.)     ❌ BROKEN      Missing the link between leaf & root
  Leaf + Inter. + Root        ⚠️  SUBOPTIMAL  Works but wastes bytes; root can't
                                             establish trust from the wire

  Key insight: If a client doesn't have the Root CA in its trust
  store, sending it won't help — a client will never trust a Root CA
  just because a random server handed it over. Trust stores are curated
  by OS vendors (Apple, Microsoft, Mozilla) after extensive vetting,
  not crowd-sourced from random TLS connections.

  See also: peep docs aia
`,
	}
}

func topicCiphers() Topic {
	return Topic{
		Name:    "ciphers",
		Title:   "Cipher Suites — What They Are and Why They Matter",
		Summary: "Cipher suites explained simply.",
		Content: `
🔐 Cipher Suites
━━━━━━━━━━━━━━━━━━

A cipher suite is a recipe for encryption. When your browser or other
application connects to a server, they negotiate which recipe to use.

A cipher suite name looks like this:
  TLS_AES_256_GCM_SHA384

That breaks down into:
  • Key Exchange: How the two sides share a secret key (e.g., ECDHE)
  • Authentication: How the server proves its identity (e.g., RSA, ECDSA)
  • Encryption: How the actual data is encrypted (e.g., AES-256-GCM)
  • MAC/Hash: How data integrity is verified (e.g., SHA384)

✅ GOOD CIPHER SUITES (use these):
  • Anything with AES-GCM or ChaCha20-Poly1305
  • Anything with ECDHE (provides Forward Secrecy)
  • TLS 1.3 suites (they're all good by design)

⚠️  OKAY BUT AGING:
  • AES-CBC modes (vulnerable to padding oracle attacks in some configs)
  • RSA key exchange without ECDHE (no Forward Secrecy)

❌ BAD CIPHER SUITES (avoid these):
  • RC4 — Broken. Banned by RFC 7465.
  • DES / 3DES — Too slow and too weak.
  • NULL encryption — Literally no encryption at all.
  • EXPORT ciphers — Intentionally weakened. A Cold War relic.

💡 FORWARD SECRECY:
  If a cipher suite has "ECDHE" or "DHE," it has Forward Secrecy.
  This means that even if someone steals the server's private key LATER,
  they can't decrypt past conversations. It's like a self-destructing message.

⚡ TLS 1.2 vs TLS 1.3 — CIPHER DIFFERENCES:
  TLS 1.2:
    • 300+ possible cipher suites (many of them bad)
    • The client sends a list; the server picks one
    • You CAN negotiate weak/insecure suites if configured poorly
    • Cipher suite name includes key exchange + auth + cipher + MAC
      Example: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

  TLS 1.3:
    • Only 5 cipher suites exist (all secure)
    • Key exchange is separate — always ECDHE or DHE (Forward Secrecy)
    • No more RSA key exchange, no more CBC, no more RC4
    • Cipher suite name is simpler — just cipher + hash
      Example: TLS_AES_128_GCM_SHA256

🌐 HTTP/2 CIPHER REQUIREMENTS:
  HTTP/2 has a blacklist of cipher suites that are NOT allowed, even if
  TLS 1.2 would normally accept them. Key restrictions:
  • AES-CBC suites are blacklisted (only AES-GCM or ChaCha20 allowed)
  • RSA key exchange (without ECDHE) is blacklisted
  • Minimum TLS 1.2 is required (in practice, most use TLS 1.3)
  • If your server offers only CBC ciphers, HTTP/2 connections will fail
    even though plain HTTPS (HTTP/1.1) might work fine
  💡 If HTTP/2 works but HTTP/1.1 falls back to a weaker cipher, that's
     a sign your server's cipher config needs attention.

──────────────────────────────────────────────────────
☠️  WHY SPECIFIC CIPHERS ARE DANGEROUS
──────────────────────────────────────────────────────

  Cipher/Mode     Attack           Year   Impact
  ──────────────  ───────────────  ─────  ──────────────────────────────────
  RC4             Bar-mitzvah/     2013+  Statistical biases leak plaintext;
                  Royal cipher            banned by RFC 7465 (2015)
  AES-CBC         BEAST            2011   Chosen-plaintext IV attack on
                                          TLS 1.0 CBC; client-side exploit
  AES-CBC         Lucky13          2013   Timing side-channel in CBC
                                          padding verification
  SSLv3 + CBC     POODLE           2014   Padding oracle; killed SSL 3.0
  3DES/Blowfish   Sweet32          2016   Birthday-bound collision after
                                          ~32 GB; practical in long sessions
  DES             Brute force      1999   56-bit key cracked in <24 hrs
  NULL            (none needed)    —      Literally no encryption at all
  EXPORT          FREAK/Logjam     2015   Intentionally weak keys (40–512
                                          bit); Cold War–era US export law

──────────────────────────────────────────────────────
🔑 FORWARD SECRECY — ECDHE vs RSA KEY EXCHANGE
──────────────────────────────────────────────────────

  Forward Secrecy (aka Perfect Forward Secrecy / PFS) means that
  compromising the server's long-term private key does NOT compromise
  past TLS sessions. Each session uses a fresh, ephemeral key pair.

  Key Exchange   Forward Secrecy?   How it works
  ───────────    ────────────────   ──────────────────────────────────
  RSA            ❌ No               Client encrypts a secret with the
                                    server's RSA public key. If that
                                    key leaks, all past traffic is
                                    decryptable. Game over.
  ECDHE          ✅ Yes              Both sides generate a fresh
                                    elliptic-curve key pair PER
                                    session. The shared secret is
                                    never transmitted. If the server's
                                    long-term key leaks, past sessions
                                    are safe.
  DHE            ✅ Yes              Same idea as ECDHE, but with
                                    classical Diffie-Hellman. Slower
                                    and requires larger parameters.

  ⚠️  TLS 1.3 removed RSA key exchange entirely.
  💡 If your cipher suite name contains "ECDHE" or "DHE," you have
     Forward Secrecy. If it starts with "TLS_RSA_WITH_", you don't.

──────────────────────────────────────────────────────
🛡️ AEAD vs CBC — ENCRYPTION MODES
──────────────────────────────────────────────────────

  AEAD (Authenticated Encryption with Associated Data):
    • Encrypts AND authenticates in a single operation
    • Examples: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305
    • Immune to padding oracle attacks (no padding!)
    • TLS 1.3 ONLY allows AEAD ciphers

  CBC (Cipher Block Chaining):
    • Encrypts in blocks, then uses a separate MAC for authentication
    • Vulnerable to timing attacks (Lucky13), padding oracles (POODLE)
    • The encrypt-then-MAC vs MAC-then-encrypt debate haunted TLS for years
    • Still allowed in TLS 1.2 but blacklisted by HTTP/2

  Rule of thumb: If the cipher name ends in "-GCM" or is "ChaCha20-
  Poly1305," it's AEAD. If it says "-CBC," it's the old mode.

──────────────────────────────────────────────────────
🚫 HTTP/2 CIPHER BLACKLIST — DETAILS
──────────────────────────────────────────────────────

  RFC 7540 (HTTP/2) maintains a blacklist of TLS 1.2 cipher suites
  that MUST NOT be used with HTTP/2. Key entries:

  • All AES-CBC suites (e.g., TLS_RSA_WITH_AES_128_CBC_SHA)
  • All RC4 suites
  • All NULL / anon / EXPORT suites
  • Static RSA key exchange (no forward secrecy)
  • 3DES suites

  If your server negotiates an HTTP/2 connection with a blacklisted
  cipher, the client MUST treat it as a connection error (INADEQUATE_
  SECURITY). In practice, browsers will fall back to HTTP/1.1.

  💡 If peep shows HTTP/2 but a CBC cipher → something is misconfigured.
     If peep shows HTTP/1.1 when you expected HTTP/2 → check ciphers.
`,
	}
}

func topicStartTLS() Topic {
	return Topic{
		Name:    "starttls",
		Title:   "STARTTLS — Upgrading Plaintext to Encrypted",
		Summary: "What STARTTLS is and which protocols use it.",
		Content: `
⬆️  STARTTLS — The Upgrade Path
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

STARTTLS is NOT a protocol — it's a command that tells a server:
"Hey, let's switch from plaintext to encrypted."

HOW IT WORKS:
  1. Client connects via plaintext TCP
  2. Client sends a protocol-specific command (e.g., EHLO for SMTP)
  3. Server advertises that it supports STARTTLS
  4. Client sends the STARTTLS command
  5. Both sides perform a TLS handshake
  6. Connection is now encrypted 🔒

PROTOCOLS THAT USE STARTTLS:
  • SMTP (ports 25, 587) — Email sending
  • LDAP (port 389) — Directory services
  • IMAP (port 143) — Email reading
  • POP3 (port 110) — Email reading (legacy)
  • FTP (port 21) — File transfer
  • XMPP — Chat/messaging

PROTOCOLS THAT USE IMPLICIT TLS (no STARTTLS needed):
  • HTTPS (port 443) — Web
  • SMTPS (port 465) — Email sending (direct TLS)
  • LDAPS (port 636) — Directory services (direct TLS)
  • IMAPS (port 993) — Email reading (direct TLS)

🎯 WHY THIS MATTERS FOR TROUBLESHOOTING:
  You can't just run "openssl s_client -connect server:587" to check
  an SMTP cert. You need the "-starttls smtp" flag, or use a tool
  like peep that handles it automatically.

💡 peep auto-detects STARTTLS protocols by port number, or you can
  force it with: peep --proto smtp server:587
`,
	}
}

func topicRDP() Topic {
	return Topic{
		Name:    "rdp",
		Title:   "RDP — Why RDP Certificates Are Special",
		Summary: "Why RDP needs special handling for cert inspection.",
		Content: `
🖥️  RDP — The Diva of Protocols
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

RDP (Remote Desktop Protocol) on port 3389 is... special.

Unlike HTTPS, you can't just connect and do a TLS handshake. RDP
requires a multi-step negotiation before it will even consider TLS:

  1. Client sends an X.224 Connection Request
     (This is a legacy ISO transport layer protocol)
  2. In that request, the client says "I want to use TLS"
  3. Server responds with X.224 Connection Confirm
     (Either agreeing to TLS or suggesting something else)
  4. ONLY THEN does the TLS handshake begin

This is why:
  ❌ openssl s_client -connect server:3389    — DOESN'T WORK
  ❌ curl https://server:3389                 — DOESN'T WORK
  ✅ peep server:3389                         — WORKS! ✨

🎯 COMMON RDP CERT ISSUES:
  • Self-signed certs — Windows generates a self-signed cert by default.
    This is normal for internal RDP, but causes browser-like warnings.
  • Wrong hostname — The cert might be issued to the server's internal
    name, but you're connecting via external DNS.
  • Expired certs — The auto-generated cert eventually expires and
    Windows doesn't always auto-renew it.
  • NLA (Network Level Authentication) — If NLA is required, RDP uses
    PROTOCOL_HYBRID (CredSSP), which adds another layer of authentication
    on top of TLS.

💡 peep automatically handles the X.224 negotiation when it sees
  port 3389. No special flags needed.
`,
	}
}

func topicTroubleshooting() Topic {
	return Topic{
		Name:    "troubleshooting",
		Title:   "Troubleshooting — Common Issues and What to Check",
		Summary: "Common TLS problems and what to check first.",
		Content: `
🔧 Troubleshooting Guide
━━━━━━━━━━━━━━━━━━━━━━━━━

When something's wrong with TLS, here's your checklist:

1️⃣  CERT EXPIRED?
   Run: peep <host>
   Look for: ❌ in the expiry line
   Fix: Renew the certificate from your CA

2️⃣  WRONG CERT / HOSTNAME MISMATCH?
   Run: peep <host>
   Look for: "❌ Hostname does NOT match"
   Fix: Get a cert that covers the correct hostname/domain
   Check the SANs (Subject Alternative Names) — the CN alone isn't enough

3️⃣  MISSING INTERMEDIATE?
   Run: peep chain <host>
   Look for: "❌ Missing intermediate certificate"
   Fix: Download the intermediate cert from your CA and install it
   alongside the leaf cert

4️⃣  WRONG CHAIN ORDER?
   Run: peep chain <host>
   Look for: "❌ Chain order is wrong"
   Fix: Re-concatenate your cert files: leaf cert first, then intermediate(s)

5️⃣  OLD TLS VERSION?
   Run: peep <host>
   Look for: ❌ on TLS version
   Fix: Disable TLS 1.0 and 1.1 in your server config

6️⃣  WEAK CIPHER SUITE?
   Run: peep <host>
   Look for: ❌ on cipher suite
   Fix: Update your server's cipher suite configuration to prefer
   AES-GCM and ECDHE-based suites

7️⃣  CONNECTION REFUSED / TIMEOUT?
   Possible causes:
   • Firewall blocking the port
   • Service not running
   • Wrong port number
   • DNS resolution issues
   Fix: Check if the port is open with: nc -zv <host> <port>

8️⃣  SELF-SIGNED CERT?
   Run: peep <host>
   Look for: "🔄 Self-signed"
   Note: This might be intentional for internal services.
   If it's public-facing, get a real cert (Let's Encrypt is free!).

9️⃣  CIPHER SUITE MISMATCH?
   Symptom: "handshake failure" or "no shared cipher" errors
   What it means: The client and server couldn't agree on an encryption
   algorithm. They each have a list of cipher suites they support, and
   if those lists have ZERO overlap, the connection fails.
   Common causes:
   • Server only allows modern ciphers (TLS 1.3) but client is old
   • Client requires strong ciphers but server still offers only legacy ones
   • Hardened server config disabled suites the client needs
   • FIPS-mode clients that only allow a specific subset of ciphers
   Run: peep scan <host> to see which cipher suites the server supports
   Fix: Compare the server's supported suites with what the client needs.
   One side needs to add support for a suite the other already has.
   💡 If the server is yours, update the cipher suite config.
      If the client is yours, update or patch the client.
      If neither is yours... good luck.

💡 PRO TIP: Use -v for detailed cert info, or -vv for PEM encoded certs:
   peep -v <host>
`,
	}
}

func topicCRL() Topic {
	return Topic{
		Name:    "crl",
		Title:   "CRL — Certificate Revocation Lists",
		Summary: "How CRLs work, freshness, HTTPS pitfalls, and CRL vs OCSP.",
		Content: `
🗑️  CRL — Certificate Revocation Lists
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

A CRL is a signed list of revoked certificate serial numbers published
by a Certificate Authority (CA). When a cert is compromised, stolen,
or decommissioned early, the CA adds its serial to the CRL so relying
parties know to reject it.

──────────────────────────────────────────────────────
📍 CRL DISTRIBUTION POINTS (CDPs)
──────────────────────────────────────────────────────

  CDPs are URLs embedded in the certificate's X.509 extensions that
  tell clients where to download the CRL. A certificate can have
  multiple CDPs for redundancy. Example (from a cert extension):

    CRL Distribution Points:
      URI: http://crl.example-ca.com/intermediate.crl

  💡 CDPs are usually HTTP (not HTTPS) — see below for why.

──────────────────────────────────────────────────────
🔄 CRL LIFECYCLE
──────────────────────────────────────────────────────

  Every CRL contains two critical timestamps:

  Field           Meaning
  ─────────────   ──────────────────────────────────────────
  ThisUpdate      When this CRL was published / became valid
  NextUpdate      When clients should fetch a newer CRL

  Typical refresh intervals:
    • Public CAs: every 1–7 days
    • Enterprise / internal CAs: every 1–24 hours
    • High-security environments: every 1–6 hours

──────────────────────────────────────────────────────
⏰ FRESHNESS & STALENESS
──────────────────────────────────────────────────────

  When NextUpdate passes and a client can't fetch a newer CRL:
    • Some clients reject the cert outright (hard-fail)
    • Some clients proceed anyway (soft-fail) — this is the default
      in most browsers
    • Some clients use cached CRLs for a grace period

  A stale CRL is dangerous: if a cert was revoked AFTER the last CRL
  was published, clients with the stale CRL won't know. They'll accept
  a compromised certificate as valid.

──────────────────────────────────────────────────────
🐔 HTTPS CRL ENDPOINTS — THE CHICKEN-AND-EGG PROBLEM
──────────────────────────────────────────────────────

  Why are most CDP URLs plain HTTP instead of HTTPS?

  To validate an HTTPS CRL endpoint, the client needs to verify the
  endpoint's own TLS certificate. That cert might itself need a CRL
  check — creating a circular dependency. The client can't validate
  the CRL server's cert without a CRL, and can't get the CRL without
  validating the server.

  This is why almost all CDPs use HTTP:
    ✅ http://crl.digicert.com/sha2-ev.crl     ← Standard
    ❌ https://crl.digicert.com/sha2-ev.crl    ← Chicken-and-egg!

  CRLs are cryptographically signed by the CA anyway, so transport-
  layer encryption isn't needed for integrity — only for privacy
  (which CRLs don't typically require).

──────────────────────────────────────────────────────
🚫 CERTS WITHOUT CDPs
──────────────────────────────────────────────────────

  Some certificates don't include CRL Distribution Points at all.
  Reasons:
    • The CA uses OCSP exclusively (see: peep docs ocsp)
    • Short-lived certs (e.g., Let's Encrypt — 90-day certs with
      OCSP but no CRL for end-entity certs)
    • Internal/private PKI with its own revocation mechanism
    • Root CA certs (roots are never revoked via CRL — they're
      removed from the trust store directly by OS vendors)

──────────────────────────────────────────────────────
📋 REVOCATION REASON CODES
──────────────────────────────────────────────────────

  When a CA revokes a certificate, it assigns a reason code:

  Code  Reason                 When it's used
  ────  ─────────────────────  ───────────────────────────────────────
  0     Unspecified            Default when no specific reason given
  1     Key Compromise         Private key leaked or stolen
  2     CA Compromise          The issuing CA's key was compromised
  3     Affiliation Changed    Org changed (e.g., company acquisition)
  4     Superseded             Replaced by a newer certificate
  5     Cessation of Operation Service shut down, domain abandoned
  6     Certificate Hold       Temporarily suspended (can be unrevoked)
  8     Remove from CRL        Used to "un-hold" a cert (code 6)
  9     Privilege Withdrawn    Authorization to hold cert was revoked
  10    AA Compromise          Attribute Authority was compromised

  ⚠️  Code 7 is unused (there is no reason code 7).
  💡 Code 1 (Key Compromise) is the scariest — it means someone else
     may have the private key and can impersonate the server.

──────────────────────────────────────────────────────
⚖️  CRL vs OCSP — COMPARISON
──────────────────────────────────────────────────────

  Feature              CRL                     OCSP
  ─────────────────    ──────────────────────  ──────────────────────
  Model                Download full list       Query per-certificate
  Latency              High (download whole     Low (single request)
                       file, can be MBs)
  Freshness            Periodic (hours/days)    Near real-time
  Bandwidth            Heavy (grows with        Light (single cert)
                       revocations)
  Privacy              Better (local check,     Worse without stapling
                       CA doesn't see queries)  (CA sees every site)
  Offline support      Yes (cached CRL works)   No (needs network)
  Server support       Not needed               Can be stapled (preferred)
  Browser support      Declining (Chrome         Mixed (Firefox uses
                       removed CRL checking)    CRLite instead)

  💡 Modern best practice: OCSP Stapling + CRL as fallback.
     See also: peep docs ocsp
`,
	}
}

func topicOCSP() Topic {
	return Topic{
		Name:    "ocsp",
		Title:   "OCSP — Online Certificate Status Protocol",
		Summary: "Stapled vs live OCSP, status meanings, Must-Staple, and privacy.",
		Content: `
🔎 OCSP — Online Certificate Status Protocol
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

OCSP is a real-time protocol for checking whether a specific
certificate has been revoked. Instead of downloading an entire CRL,
the client (or server) sends a single query for one certificate's
serial number and gets back a signed response: Good, Revoked, or
Unknown.

──────────────────────────────────────────────────────
📡 TWO MODES: STAPLED vs LIVE
──────────────────────────────────────────────────────

  1. OCSP Stapling (server-side, preferred):
     • The SERVER periodically fetches the OCSP response from the CA
     • During the TLS handshake, the server "staples" the response
       to the Certificate message
     • The client gets proof of freshness without contacting the CA
     • No privacy leak — the CA never sees who's visiting the site
     • ✅ Fast, private, and reliable

  2. Live OCSP Query (client-side):
     • The CLIENT connects to the CA's OCSP responder during the
       TLS handshake
     • Adds latency (extra network round-trip)
     • The CA sees every site the client visits (privacy issue)
     • If the OCSP responder is down, the client must decide:
       proceed (soft-fail) or abort (hard-fail)
     • ❌ Slow, leaks privacy, fragile

──────────────────────────────────────────────────────
🔗 OCSP RESPONDER URLs
──────────────────────────────────────────────────────

  The OCSP responder URL is found in the certificate's Authority
  Information Access (AIA) extension:

    Authority Information Access:
      OCSP - URI: http://ocsp.digicert.com

  Like CRL CDPs, OCSP responder URLs are typically HTTP (not HTTPS)
  to avoid the chicken-and-egg TLS validation problem.

──────────────────────────────────────────────────────
📊 STATUS MEANINGS
──────────────────────────────────────────────────────

  Status     Meaning
  ─────────  ────────────────────────────────────────────────
  Good       Certificate is NOT revoked (as of ThisUpdate)
  Revoked    Certificate IS revoked — stop trusting it!
  Unknown    OCSP responder doesn't know about this cert
             (could mean wrong responder, CA doesn't track
             it, or serial number not in CA's database)

  ⚠️  "Good" only means "not revoked" — it does NOT validate expiry,
     hostname, key strength, or anything else about the cert.

──────────────────────────────────────────────────────
⏰ FRESHNESS: ProducedAt, ThisUpdate, NextUpdate
──────────────────────────────────────────────────────

  Field           Meaning
  ─────────────   ──────────────────────────────────────────
  ProducedAt      When the OCSP responder generated this response
  ThisUpdate      The most recent time the status was confirmed
  NextUpdate      When the client should fetch a fresh response

  If NextUpdate has passed and a new response can't be fetched, the
  stapled response is considered stale. Clients may reject it (strict
  mode) or proceed anyway (lenient mode).

──────────────────────────────────────────────────────
📌 OCSP MUST-STAPLE
──────────────────────────────────────────────────────

  The "OCSP Must-Staple" extension (RFC 7633, OID 1.3.6.1.5.5.7.1.24)
  is set in the certificate itself. When present:

    • The server MUST include a stapled OCSP response
    • If the staple is missing, the client MUST reject the connection
    • This eliminates soft-fail — if the OCSP status can't be verified,
      the connection dies

  💡 Must-Staple is opt-in per certificate. It's the strongest
     revocation enforcement available in TLS today.

  ⚠️  If your server doesn't support OCSP stapling and you enable
     Must-Staple on the cert, ALL connections will fail. Test first.

──────────────────────────────────────────────────────
🤷 SOFT-FAIL vs HARD-FAIL
──────────────────────────────────────────────────────

  What happens when the client can't reach the OCSP responder?

  Mode         Behavior                    Who does this
  ───────────  ────────────────────────    ─────────────────────────
  Soft-fail    Proceed anyway              Most browsers (Chrome,
               (assume "Good")             Safari, Edge)
  Hard-fail    Reject the connection       Firefox (with CRLite),
               (assume "Revoked")          some enterprise configs

  The problem with soft-fail: an attacker who compromises a cert's
  private key can ALSO block OCSP queries (by MITMing the OCSP
  responder URL). The client soft-fails, and the revoked cert works.

  The problem with hard-fail: if the OCSP responder has an outage,
  EVERY site using that CA becomes unreachable. CAs have outages.

──────────────────────────────────────────────────────
🦊 CRLite (FIREFOX)
──────────────────────────────────────────────────────

  Firefox takes a different approach entirely: CRLite.

  Instead of querying OCSP or downloading CRLs, Mozilla pre-computes
  a compressed bloom-filter of ALL revoked certificates and pushes it
  to every Firefox installation via Remote Settings.

  Benefits:
    • No real-time queries (no privacy leak, no latency)
    • Hard-fail without fragility (data is pre-distributed)
    • Covers ALL certificates, not just the one being checked
    • Updated multiple times per day

  This is why Firefox can hard-fail on revocation without causing
  outages. Other browsers haven't adopted this approach yet.

──────────────────────────────────────────────────────
🔒 PRIVACY — THE HIDDEN COST OF LIVE OCSP
──────────────────────────────────────────────────────

  Without OCSP stapling, every time a client connects to a site, it
  also tells the CA which site it's visiting. The CA's OCSP responder
  receives:
    • The certificate serial number (identifies the site)
    • The client's IP address
    • The timestamp

  This creates a browsing history at the CA level. CAs promise not to
  use this data, but the capability exists.

  OCSP Stapling eliminates this entirely — the server fetches the
  response, the client never contacts the CA.

  💡 This is one of the strongest arguments for OCSP Stapling.
     See also: peep docs aia
`,
	}
}

func topicAIA() Topic {
	return Topic{
		Name:    "aia",
		Title:   "AIA — Authority Information Access & Browser Magic",
		Summary: "How browsers fetch missing certs, and why \"works in Chrome\" isn't enough.",
		Content: `
🪄 AIA — Authority Information Access & Browser Magic
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

AIA is an X.509 certificate extension that contains two important URLs:

  1. caIssuers — URL to download the issuing CA's certificate
     (the intermediate that signed this cert)
  2. OCSP — URL of the OCSP responder for revocation checks

Example (from a cert's extensions):
  Authority Information Access:
    CA Issuers - URI: http://certs.digicert.com/DigiCertSHA2EV.crt
    OCSP - URI: http://ocsp.digicert.com

──────────────────────────────────────────────────────
🔍 AIA CHASING — HOW BROWSERS FETCH MISSING INTERMEDIATES
──────────────────────────────────────────────────────

  When a server doesn't send the intermediate certificate, some
  clients can "chase" the AIA caIssuers URL to fetch the missing cert:

    1. Client receives the leaf cert from the server
    2. Leaf cert has AIA caIssuers → http://certs.ca.com/intermediate.crt
    3. Client downloads the intermediate
    4. Client builds the chain: leaf → intermediate → root
    5. Connection succeeds ✅

  This is called "AIA chasing" or "AIA fetching."

──────────────────────────────────────────────────────
💥 THE "WORKS IN CHROME BUT BREAKS EVERYWHERE ELSE" PROBLEM
──────────────────────────────────────────────────────

  Chrome (and most browsers) do AIA chasing automatically. So if your
  server is missing the intermediate cert, Chrome will silently fetch
  it and everything looks fine.

  But these clients do NOT do AIA chasing:
    ❌ curl / wget / libcurl-based tools
    ❌ OpenSSL CLI (openssl s_client)
    ❌ Python (requests, urllib3, httpx)
    ❌ Go (net/http)
    ❌ Java (HttpsURLConnection, OkHttp)
    ❌ Node.js (https module)
    ❌ Mobile apps (iOS URLSession, Android OkHttp)
    ❌ IoT devices and embedded systems
    ❌ API gateways and service mesh proxies

  These clients expect the server to send the complete chain. If the
  intermediate is missing, they fail with errors like:
    • "unable to get local issuer certificate"
    • "SSL certificate problem: unable to verify"
    • "PKIX path building failed"
    • "certificate verify failed"

  💡 peep deliberately does NOT do AIA chasing — it shows you what
     non-browser clients see. If peep reports a missing intermediate,
     your server is broken for a large portion of the Internet.

──────────────────────────────────────────────────────
🍎 macOS KEYCHAIN MAGIC
──────────────────────────────────────────────────────

  macOS has an extra layer of "helpful" behavior: the system Keychain
  caches intermediate certificates globally. If Safari or any macOS
  app fetches an intermediate via AIA, it gets stored in the Keychain
  and is available to ALL apps on that machine.

  This means:
    • You visit a site in Safari → intermediate gets cached
    • You run curl → curl "works" because macOS provides the cached
      intermediate from the Keychain
    • You think your server's chain is fine
    • You deploy to a Linux server / Docker container / CI → BROKEN

  peep bypasses the macOS Keychain deliberately. It verifies the chain
  using ONLY the certificates the server sent in the TLS handshake,
  plus the system root trust store. No AIA chasing, no cached
  intermediates. What peep shows you is what curl on a fresh Linux
  box would see.

──────────────────────────────────────────────────────
🛡️  WHY YOU CAN'T TRUST A ROOT CA FROM THE WIRE
──────────────────────────────────────────────────────

  Sometimes people ask: "If the server sends the root CA cert, why
  doesn't the client just trust it?"

  Because that would defeat the entire purpose of certificate security.

  Trust stores are curated lists of Root CAs maintained by:
    • Apple (macOS, iOS)
    • Microsoft (Windows)
    • Mozilla (Firefox, used by many Linux distros)
    • Google (Chrome Root Program)

  These vendors vet CAs through extensive audits (WebTrust, ETSI),
  require compliance with CA/Browser Forum Baseline Requirements,
  and can REMOVE CAs that misbehave (see: Symantec, WoSign, CNNIC).

  If any server could make a client trust a new Root CA just by
  sending it during a TLS handshake, an attacker could:
    1. Create their own Root CA
    2. Issue a cert for any domain (google.com, your-bank.com)
    3. MITM your connection and send their fake root + fake cert
    4. Your client would "trust" it → complete security failure

  This is why root CAs are NEVER trusted from the wire. They must
  be pre-installed in the OS trust store through a controlled process.

──────────────────────────────────────────────────────
📦 THE CORRECT CHAIN COMPOSITION
──────────────────────────────────────────────────────

  What the server should send:

    ✅ Leaf cert + Intermediate(s)

  What the server should NOT send:

    ❌ Leaf only (broken for non-AIA clients)
    ❌ Leaf + Root (missing intermediate, root is wasted bytes)
    ⚠️  Leaf + Intermediate + Root (works, but root is dead weight)

  The root cert belongs in the trust store, not in the TLS handshake.

  See also: peep docs chain, peep docs ocsp, peep docs crl
`,
	}
}
