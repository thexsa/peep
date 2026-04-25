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
		topicCerts(),
		topicChain(),
		topicCiphers(),
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

💡 FUN FACT:
  "SSL" and "TLS" are often used interchangeably, but SSL is technically
  dead. When someone says "SSL certificate," they mean a certificate used
  with TLS. It's like calling every tissue a "Kleenex."
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

A cipher suite is a recipe for encryption. When your browser connects
to a server, they negotiate which recipe to use.

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
