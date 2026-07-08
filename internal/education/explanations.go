package education

import (
	"fmt"
	"math/rand"
	"strings"

	"github.com/thexsa/peep/internal/analyzer"
)

// isNetworkError returns true if the error string indicates a network-level
// failure (timeout, connection refused, DNS, etc.) rather than a server-side
// or data integrity issue. These failures may reflect the scanner's network
// path rather than the server's TLS configuration.
func isNetworkError(errStr string) bool {
	lower := strings.ToLower(errStr)
	patterns := []string{
		"timeout",
		"i/o timeout",
		"connection refused",
		"no such host",
		"network is unreachable",
		"no route to host",
		"connection reset",
		"dial tcp",
		"dial udp",
		"context deadline exceeded",
		"tls handshake timeout",
		"eof",
		"connection timed out",
	}
	for _, p := range patterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// BrowserSafeWarningCodes lists warning codes that modern browsers handle
// gracefully. These warnings are suppressed (treated as MainCharacterEnergy)
// when computing the Browser verdict, but remain at full severity for the
// Service/API verdict.
//
// Modern browsers dynamically rebuild chains, soft-fail on OCSP/CRL,
// and don't block on missing SCTs. Programmatic clients (Go crypto/tls,
// OpenSSL, Java) enforce strict chain order, revocation, and reject aggressively.
//
// NOTE: CHAIN_MISSING_INTERMEDIATE is intentionally NOT browser-safe.
// Chrome/Firefox attempt AIA fetching, but it's unreliable, adds latency,
// and Safari doesn't always support it.
var BrowserSafeWarningCodes = map[string]bool{
	// Chain issues browsers auto-fix
	"CHAIN_WRONG_ORDER":      true, // Browsers rebuild chain order dynamically
	"CHAIN_UNNECESSARY_ROOT": true, // Browsers ignore extra root certs

	// OCSP — browsers soft-fail by default
	"OCSP_STAPLE_MISSING":  true, // Browsers do their own OCSP or skip it
	"OCSP_STAPLE_STALE":    true, // Browsers soft-fail stale staples
	"OCSP_UNKNOWN":         true, // Browsers soft-fail "unknown" responses
	"OCSP_ERROR":           true, // Browsers soft-fail OCSP errors
	"OCSP_NETWORK_ERROR":   true, // Already info — scanner network issue

	// CRL — browsers use CRLite/CRLSets, don't fetch CRLs live
	"CRL_STALE":         true,
	"CRL_FETCH_FAILED":  true,
	"CRL_NETWORK_ERROR": true, // Already info — scanner network issue

	// CT — Chrome uses its own CT infra; missing SCTs alone don't block
	"CT_NO_SCTS":    true,
	"CT_PARSE_ERROR": true,

	// Validity period — browsers warn but don't block on long validity
	"CERT_LONG_VALIDITY": true,
	"CERT_VALIDITY_PERIOD": true,
}

// PublicCAOnlyWarningCodes are warning codes that only apply to publicly-trusted CAs.
// These are suppressed when the CA origin detection determines the CA is private/internal.
// Private CAs don't submit to CT logs and aren't bound by CA/B Forum validity limits.
var PublicCAOnlyWarningCodes = map[string]bool{
	"CT_NO_SCTS":         true, // Private CAs don't participate in CT
	"CT_PARSE_ERROR":     true, // SCTs are a public CA concept
	"CERT_LONG_VALIDITY": true, // CA/B Forum 398-day limit is for public CAs only
	"CERT_VALIDITY_PERIOD": true, // Same — internal certs commonly have longer validity
}

// SuppressPublicCAOnlyWarnings removes warnings that only apply to public CAs
// from the warning list. Called after CA origin detection determines the CA
// is private/internal (assessment is "very_likely_private_ca", "likely_private_ca",
// or "possibly_private_ca").
func SuppressPublicCAOnlyWarnings(warnings []analyzer.Warning) []analyzer.Warning {
	filtered := make([]analyzer.Warning, 0, len(warnings))
	for _, w := range warnings {
		if PublicCAOnlyWarningCodes[w.Code] {
			continue
		}
		filtered = append(filtered, w)
	}
	return filtered
}

// EvaluateDualVerdict computes both browser and service verdicts from a
// base grade (worst of handshake + chain grades) and a warning list.
// The service verdict is the strict worst-of-all. The browser verdict
// skips browser-safe warning codes.
func EvaluateDualVerdict(baseGrade analyzer.HealthStatus, warnings []analyzer.Warning) analyzer.DualVerdict {
	serviceVerdict := EvaluateServiceVerdict(baseGrade, warnings)
	browserVerdict := EvaluateBrowserVerdict(baseGrade, warnings)

	var rootCauses []string
	if browserVerdict != serviceVerdict {
		// Collect the warning codes responsible for the divergence
		for _, w := range warnings {
			if BrowserSafeWarningCodes[w.Code] && w.Severity > browserVerdict {
				// This warning was suppressed in browser but affects service
				rootCauses = append(rootCauses, w.Code)
			}
		}
	}

	return analyzer.DualVerdict{
		BrowserVerdict: browserVerdict,
		ServiceVerdict: serviceVerdict,
		RootCauses:     rootCauses,
	}
}

// EvaluateServiceVerdict computes the strict verdict — worst grade wins
// across all warnings, no exceptions. This is the current behavior.
func EvaluateServiceVerdict(baseGrade analyzer.HealthStatus, warnings []analyzer.Warning) analyzer.HealthStatus {
	status := baseGrade
	for _, w := range warnings {
		if w.Severity > status {
			status = w.Severity
		}
	}
	return status
}

// EvaluateBrowserVerdict computes the lenient verdict — browser-safe
// warning codes are treated as informational (MainCharacterEnergy) and
// don't drag down the overall browser compatibility verdict.
func EvaluateBrowserVerdict(baseGrade analyzer.HealthStatus, warnings []analyzer.Warning) analyzer.HealthStatus {
	status := baseGrade
	for _, w := range warnings {
		if BrowserSafeWarningCodes[w.Code] {
			continue // Skip browser-safe warnings
		}
		if w.Severity > status {
			status = w.Severity
		}
	}
	return status
}
// BuildWarnings examines a diagnostic report and generates contextual warnings.
// When internalCA is true, checks that only apply to publicly-trusted certificates
// (like the 398-day validity cap) are skipped.
func BuildWarnings(report *analyzer.DiagnosticReport, internalCA bool) []analyzer.Warning {
	var warnings []analyzer.Warning

	warnings = append(warnings, checkTLSVersion(report.Handshake)...)
	warnings = append(warnings, checkCipherSuite(report.Handshake)...)

	for _, cert := range report.Chain.Certificates {
		warnings = append(warnings, checkCert(cert)...)
		warnings = append(warnings, CheckValidityPeriodWarning(cert, internalCA)...)
	}

	warnings = append(warnings, checkChain(report.Chain)...)

	return warnings
}

func checkTLSVersion(hs analyzer.HandshakeAnalysis) []analyzer.Warning {
	var w []analyzer.Warning
	switch hs.TLSVersion {
	case "TLSv1.0":
		w = append(w, analyzer.Warning{
			Code:     "TLS_V10",
			Severity: analyzer.WrittenInCrayon,
			Title:    "Ancient TLS Version: TLS 1.0",
			Detail:   "TLS 1.0 was deprecated by RFC 8996 in March 2021.",
			Why:      pick(tlsOldSayings),
			Explain:  "TLS 1.0 (from 1999) has known vulnerabilities including BEAST and POODLE attacks. It uses a 2-round-trip handshake with weak cipher negotiation. Attackers can downgrade connections and decrypt traffic. Every major compliance framework (PCI-DSS, HIPAA, NIST) prohibits TLS 1.0.",
			Fix:      "Disable TLS 1.0 in your server configuration. Enable TLS 1.2 (minimum) or TLS 1.3 (preferred). In nginx: ssl_protocols TLSv1.2 TLSv1.3; In Apache: SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1",
			DocRef:   "peep docs tls",
		})
	case "TLSv1.1":
		w = append(w, analyzer.Warning{
			Code:     "TLS_V11",
			Severity: analyzer.WrittenInCrayon,
			Title:    "Deprecated TLS Version: TLS 1.1",
			Detail:   "TLS 1.1 was deprecated by RFC 8996 in March 2021.",
			Why:      pick(tlsOldSayings),
			Explain:  "TLS 1.1 (from 2006) was deprecated alongside TLS 1.0. While slightly better than 1.0, it still lacks modern protections like AEAD ciphers and has a slower 2-round-trip handshake. All major browsers dropped support in 2020. PCI-DSS and NIST require TLS 1.2 or higher.",
			Fix:      "Disable TLS 1.1 in your server configuration. Enable TLS 1.2 (minimum) or TLS 1.3 (preferred). Test with: peep scan <host> to verify which versions are still enabled.",
			DocRef:   "peep docs tls",
		})
	case "TLSv1.2":
		// TLS 1.2 is fine, no warning needed unless cipher is bad
	}
	return w
}

func checkCipherSuite(hs analyzer.HandshakeAnalysis) []analyzer.Warning {
	var w []analyzer.Warning
	if hs.CipherGrade == analyzer.WrittenInCrayon {
		w = append(w, analyzer.Warning{
			Code:     "CIPHER_INSECURE",
			Severity: analyzer.WrittenInCrayon,
			Title:    "Insecure Cipher Suite: " + hs.CipherSuite,
			Detail:   "This cipher suite is classified as insecure.",
			Why:      pick(cipherInsecureSayings),
			Explain:  "This cipher suite has known cryptographic weaknesses. Depending on the specific suite, it may be vulnerable to attacks like BEAST, POODLE, Sweet32, or Lucky13. Insecure ciphers can allow attackers to decrypt traffic, forge data, or downgrade connections. Note: HTTP/2 has a blacklist of cipher suites — using an insecure cipher may also break HTTP/2 connections.",
			Fix:      "Update your server's cipher suite configuration to use only secure options: AES-128-GCM, AES-256-GCM, or ChaCha20-Poly1305 with ECDHE key exchange. Disable RC4, DES, 3DES, NULL, EXPORT, and CBC-mode ciphers. Use: peep scan <host> to see all supported cipher suites.",
			DocRef:   "peep docs ciphers",
		})
	}
	return w
}

func checkCert(cert analyzer.CertAnalysis) []analyzer.Warning {
	var w []analyzer.Warning

	if cert.IsExpired {
		w = append(w, analyzer.Warning{
			Code:     "CERT_EXPIRED",
			Severity: analyzer.WrittenInCrayon,
			Title:    certPrefix(cert) + "Certificate EXPIRED",
			Detail:   "This certificate expired " + pluralDays(-cert.DaysRemaining) + " ago.",
			Why:      pick(certExpiredSayings),
			Explain:  "An expired certificate means EVERY client connecting to this server will see a security warning or outright connection failure. Browsers show a full-page error. APIs return TLS errors. Automated systems stop working. The certificate's validity period is cryptographically enforced — there is no workaround except renewal.",
			Fix:      "Renew the certificate immediately from your CA (Certificate Authority). If using Let's Encrypt, run: certbot renew. If using a commercial CA, reissue from their portal. After renewal, install the new cert and restart the service.",
			DocRef:   "peep docs certs",
		})
	} else if cert.DaysRemaining <= 14 {
		w = append(w, analyzer.Warning{
			Code:     "CERT_EXPIRING_SOON",
			Severity: analyzer.WrittenInCrayon,
			Title:    certPrefix(cert) + "Certificate Expiring VERY Soon",
			Detail:   "This certificate expires in " + pluralDays(cert.DaysRemaining) + ".",
			Why:      pick(certExpiringSoonSayings),
			Explain:  "With less than 14 days until expiry, this certificate is in the danger zone. Certificate renewals can take time — CA validation, DNS propagation, deployment, and testing. If this expires, all clients will see security errors and connections will fail. Many organizations require 30+ days lead time for cert renewals.",
			Fix:      "Renew this certificate NOW. Don't wait. If using Let's Encrypt: certbot renew. If using a commercial CA, log into their portal and reissue. Deploy the new cert and verify with: peep <host>",
			DocRef:   "peep docs certs",
		})
	} else if cert.DaysRemaining <= 30 {
		w = append(w, analyzer.Warning{
			Code:     "CERT_EXPIRING",
			Severity: analyzer.MallCopCredentials,
			Title:    certPrefix(cert) + "Certificate Expiring Soon",
			Detail:   "This certificate expires in " + pluralDays(cert.DaysRemaining) + ".",
			Why:      pick(certExpiringSayings),
			Explain:  "This certificate is within 30 days of expiry. While it's still valid, this is the window where you should be actively renewing. Unexpected delays (CA outages, DNS issues, approval processes, vacation) can push you past the expiry date. Set up automated renewal if possible.",
			Fix:      "Start the renewal process now. For automated certs (Let's Encrypt), verify your renewal cron job is working. For commercial CAs, submit the renewal request. Consider setting up cert monitoring to avoid this in the future.",
			DocRef:   "peep docs certs",
		})
	}

	if cert.IsSelfSigned && cert.Role == analyzer.RoleLeaf {
		w = append(w, analyzer.Warning{
			Code:     "CERT_SELF_SIGNED",
			Severity: analyzer.MallCopCredentials,
			Title:    "Self-Signed Certificate",
			Detail:   "This certificate was signed by itself, not by a trusted CA.",
			Why:      pick(selfSignedSayings),
			Explain:  "A self-signed certificate has no third-party validation. It was signed by its own private key, meaning there's no chain of trust — no CA vouches for it. Every browser and most applications will show a security warning or refuse to connect. Self-signed certs are fine for development and internal testing, but in production they undermine the entire trust model of TLS.",
			Fix:      "Replace with a certificate from a trusted CA. Let's Encrypt provides free, automated certificates. For internal services, use your organization's internal CA (private PKI) and ensure the root CA cert is installed on all client devices.",
			DocRef:   "peep docs certs",
		})
	}

	if cert.KeyGrade == analyzer.WrittenInCrayon {
		w = append(w, analyzer.Warning{
			Code:     "CERT_WEAK_KEY",
			Severity: analyzer.WrittenInCrayon,
			Title:    certPrefix(cert) + "Weak Key",
			Detail:   "Key type: " + cert.KeyType + ".",
			Why:      pick(weakKeySayings),
			Explain:  "This certificate's key is too short to be considered secure. Short keys can be brute-forced with modern hardware. NIST recommends: RSA keys ≥ 2048 bits, ECDSA keys ≥ 256 bits (P-256 or higher). Keys shorter than this can be factored or broken within a practical timeframe.",
			Fix:      "Generate a new key pair with a strong key size: RSA 2048+ bits or ECDSA P-256/P-384. Then request a new certificate using the new key. Most CAs allow free reissuance.",
			DocRef:   "peep docs certs",
		})
	}

	if cert.SignatureGrade == analyzer.WrittenInCrayon {
		w = append(w, analyzer.Warning{
			Code:     "CERT_SHA1",
			Severity: analyzer.WrittenInCrayon,
			Title:    certPrefix(cert) + "Insecure Signature Algorithm: " + cert.SignatureAlg,
			Detail:   "This certificate uses a signature algorithm with known weaknesses.",
			Why:      pick(sha1Sayings),
			Explain:  "SHA-1 signatures were proven vulnerable to collision attacks in 2017 (Google's SHAttered attack). This means an attacker could potentially forge a certificate that appears valid. All major browsers stopped trusting SHA-1 signed certificates. SHA-256 (SHA-2) or higher is required.",
			Fix:      "Reissue the certificate with SHA-256 (SHA-2) or higher signature algorithm. Most CAs default to SHA-256 now. If your CA issued this with SHA-1, contact them — they may be using outdated infrastructure.",
			DocRef:   "peep docs certs",
		})
	}

	if cert.Role == analyzer.RoleLeaf && !cert.HostnameMatch {
		w = append(w, analyzer.Warning{
			Code:     "CERT_HOSTNAME_MISMATCH",
			Severity: analyzer.WrittenInCrayon,
			Title:    "Hostname Mismatch",
			Detail:   "The certificate does not cover the hostname you connected to.",
			Why:      pick(hostnameMismatchSayings),
			Explain:  "The hostname you connected to is not listed in the certificate's Subject Alternative Names (SANs). Browsers and applications verify that the cert covers the exact hostname — if it doesn't match, the connection is rejected. This usually means the wrong cert is installed, or the cert was issued for a different domain.",
			Fix:      "Check the SANs on the certificate (shown in -v output). Either: (1) install the correct certificate that covers this hostname, (2) reissue the cert to include this hostname as a SAN, or (3) verify you're connecting to the right server.",
			DocRef:   "peep docs troubleshooting",
		})
	}

	return w
}

func checkChain(chain analyzer.ChainAnalysis) []analyzer.Warning {
	var w []analyzer.Warning

	// These three flags (LeafOnlyMissingIntermediate, HasMissingIntermediate,
	// NoIssuingCAInResponse) overlap heavily — especially when the server sends
	// only the leaf cert. Emit only the most specific applicable finding to
	// avoid triple-reporting the same root cause.
	switch {
	case chain.HasWrongIntermediate:
		// Server sent an intermediate with the right name but the wrong key.
		w = append(w, analyzer.Warning{
			Code:     "CHAIN_WRONG_INTERMEDIATE",
			Severity: analyzer.WrittenInCrayon,
			Title:    "Wrong Issuing CA in Server Response",
			Detail:   "The server sent an intermediate whose name matches the leaf's issuer, but whose key did NOT sign the leaf certificate.",
			Why:      pick(wrongIntermediateSayings),
			Explain:  "The server included an intermediate certificate that has the correct issuer name (Subject DN), but its public key does not match the key that signed the leaf certificate. This happens when a CA is renewed or re-keyed — the CA gets a new key pair, but the old leaf cert was signed by the old key. The chain looks right on paper, but the cryptographic signature doesn't verify. Most clients will reject this chain entirely.",
			Fix:      "Either (1) re-issue the leaf certificate using the new CA key so the signature matches the intermediate being served, or (2) replace the intermediate on the server with the OLD intermediate cert whose key actually signed the leaf. Option 1 is the correct long-term fix. After a CA re-key, ALL leaf certs signed by the old key must be re-issued.",
			DocRef:   "peep docs chain",
		})
	case chain.LeafOnlyMissingIntermediate:
		// Most specific: server sent ONLY the leaf, and its issuer isn't a root.
		w = append(w, analyzer.Warning{
			Code:     "CHAIN_LEAF_ONLY",
			Severity: analyzer.WrittenInCrayon,
			Title:    "Incomplete Chain — Server Sent Only the Leaf Certificate",
			Detail:   "Only the leaf cert was sent. Its issuer is NOT a root CA, so the intermediate must be included.",
			Why:      pick(leafOnlySayings),
			Explain:  "During the TLS handshake, the server is expected to send the complete certificate chain: the leaf cert plus any intermediate CA certs that signed it. This server sent ONLY the leaf certificate — no issuing CA was included. The issuing CA is an intermediate CA (not a root), which means clients cannot verify the chain unless they happen to have the intermediate already installed — and most don't. Some browsers can fetch missing intermediates via AIA, but most applications, APIs, curl, mobile apps, and IoT devices will fail with a trust error.",
			Fix:      "Add the intermediate certificate to your server's cert chain. Concatenate them: cat leaf.crt intermediate.crt > fullchain.crt. In nginx: ssl_certificate should contain the full chain. In Apache: use SSLCertificateChainFile. Download the intermediate from your CA's repository. Do NOT rely on clients having the intermediate pre-installed. Verify with: peep <host>",
			DocRef:   "peep docs chain",
		})
	case chain.HasMissingIntermediate:
		// Server sent multiple certs but an intermediate is still missing.
		w = append(w, analyzer.Warning{
			Code:     "CHAIN_MISSING_INTERMEDIATE",
			Severity: analyzer.WrittenInCrayon,
			Title:    "Missing Intermediate Certificate",
			Detail:   "The server did not send all required intermediate certificates.",
			Why:      pick(missingIntermediateSayings),
			Explain:  "The server must send the complete certificate chain: leaf cert + intermediate cert(s). Without the intermediate, clients can't build a path from your leaf cert to a trusted root CA. Some browsers (like Chrome) can fetch missing intermediates via AIA, but most applications, APIs, curl, and mobile apps cannot — they will fail.",
			Fix:      "Download the correct intermediate certificate from your CA's website. Concatenate it with your leaf cert (leaf first, then intermediate). In nginx: ssl_certificate should contain both. In Apache: use SSLCertificateChainFile. Verify with: peep <host>",
			DocRef:   "peep docs chain",
		})
	case chain.NoIssuingCAInResponse:
		// Broadest: no issuing CA present (shouldn't fire if the above two didn't, but just in case).
		w = append(w, analyzer.Warning{
			Code:     "CHAIN_NO_ISSUING_CA",
			Severity: analyzer.WrittenInCrayon,
			Title:    "No Issuing CA in Server Response",
			Detail:   "The server did not include the issuing CA certificate in its TLS response.",
			Why:      pick(noIssuingCASayings),
			Explain:  "During the TLS handshake, the server is expected to send the complete certificate chain: the leaf cert plus any intermediate CA certs that signed it. This server sent only the leaf certificate — no issuing CA was included. Without the issuing CA, clients cannot build a trust path to a root CA. Some browsers may work (they can fetch intermediates via AIA), but most applications, APIs, curl, mobile apps, and IoT devices will fail with a trust error.",
			Fix:      "Add the issuing CA (intermediate) certificate to the server's cert chain. Concatenate them: cat leaf.crt intermediate.crt > fullchain.crt. In nginx: ssl_certificate should contain the full chain. In Apache: use SSLCertificateChainFile. If this is a self-signed cert, either replace it with a CA-signed cert or distribute it to all client trust stores.",
			DocRef:   "peep docs chain",
		})
	}

	if !chain.ChainOrderCorrect {
		w = append(w, analyzer.Warning{
			Code:     "CHAIN_WRONG_ORDER",
			Severity: analyzer.WrittenInCrayon,
			Title:    "Certificate Chain in Wrong Order",
			Detail:   "Certificates should be ordered: leaf → intermediate(s) → root.",
			Why:      pick(wrongOrderSayings),
			Explain:  "The TLS specification requires certificates to be sent in order: the leaf cert first, followed by the intermediate(s) that signed it, optionally ending with the root. If the chain is out of order, many TLS implementations will reject it outright or fail to build the trust path.",
			Fix:      "Re-concatenate your certificate files in the correct order: cat leaf.crt intermediate.crt > fullchain.crt. Make sure the leaf cert (the one with your domain) is FIRST in the file.",
			DocRef:   "peep docs chain",
		})
	}

	if chain.HasUnnecessaryRoot {
		w = append(w, analyzer.Warning{
			Code:     "CHAIN_UNNECESSARY_ROOT",
			Severity: analyzer.MallCopCredentials,
			Title:    "Unnecessary Root CA in Chain",
			Detail:   "The server is sending the root CA certificate, which clients already have.",
			Why:      pick(unnecessaryRootSayings),
			Explain:  "The root CA certificate is already in the client's trust store (OS/browser). Sending it in the TLS handshake wastes bandwidth on every connection — and on high-traffic servers, those extra bytes add up. Security-wise, the chain still works: the leaf and intermediate are present, so clients can build the full trust path. But here's the key insight: if a client DOESN'T have the root CA in its trust store, sending it over the wire won't help. A client will never trust a Root CA just because a random server handed it over during a handshake — that would defeat the entire point of certificate security. Trust stores are curated by OS vendors (Apple, Microsoft, Mozilla) after extensive vetting, not crowd-sourced from random TLS connections. The correct chain is: leaf → intermediate(s). No root needed. Modern browsers can also fetch missing intermediates via AIA (Authority Information Access) chasing, but non-browser clients (curl, APIs, mobile apps, IoT) cannot — so always include the intermediate, but skip the root.",
			Fix:      "Remove the root CA certificate from your server's cert chain file. Keep only the leaf and intermediate certificates. The root is already trusted by the client.",
			DocRef:   "peep docs chain",
		})
	}

	if chain.VerificationError != "" {
		w = append(w, analyzer.Warning{
			Code:     "CHAIN_VERIFICATION_FAILED",
			Severity: analyzer.WrittenInCrayon,
			Title:    "Chain Verification Failed",
			Detail:   "Trust store verification error: " + chain.VerificationError,
			Why:      pick(verificationFailedSayings),
			Explain:  "The system trust store could not verify this certificate chain. This means the chain is broken — either a cert is missing, expired, self-signed, or issued by an untrusted CA. Every client connecting to this server will see a security error. Browsers show a full-page warning. APIs get TLS errors. Automated systems fail silently or loudly.",
			Fix:      "Check the chain: (1) Is the leaf cert expired? (2) Is the intermediate cert included? (3) Is the CA trusted by the client's OS? For self-signed certs, either replace with a CA-signed cert or add the self-signed cert to the client's trust store. For missing intermediates, add them to the server's chain. Verify with: peep -v <host>",
			DocRef:   "peep docs troubleshooting",
		})
	}

	return w
}

// --- Helpers ---

func certPrefix(cert analyzer.CertAnalysis) string {
	if cert.CommonName != "" {
		return "[" + cert.CommonName + "] "
	}
	return ""
}

func pluralDays(n int) string {
	if n < 0 {
		n = -n
	}
	if n == 1 {
		return "1 day"
	}
	return fmt.Sprintf("%d days", n)
}

func pick(pool []string) string {
	return pool[rand.Intn(len(pool))]
}

// --- Saying pools ---

var tlsOldSayings = []string{
	"This protocol has more holes than Swiss cheese at a shooting range. Upgrade. Now.",
	"This version was born in 1999 — it's old enough to rent a car. And just as unreliable.",
	"Deprecated since 2021, yet here it is. Like a fax machine in a startup.",
	"NIST, PCI-DSS, and your mom all agree: stop using this.",
	"Using this TLS version is like locking your front door but leaving the windows wide open.",
	"Every vulnerability scanner on the planet is flagging this. You just don't know it yet.",
	"This was deprecated before TikTok existed. Let that sink in.",
	"Script kiddies consider this version a personal invitation.",
	"RFC 8996 killed this protocol. You're running a zombie.",
	"If TLS versions were milk, this one expired during the Obama administration.",
}

var cipherInsecureSayings = []string{
	"This cipher suite is so broken that script kiddies can crack it between YouTube videos.",
	"Whoever configured this should be banned from touching servers. Forever.",
	"This cipher has known attacks. As in, Google-it-and-find-a-tool-in-5-minutes known.",
	"Using this cipher in production is the TLS equivalent of a 'password123' password.",
	"There are literal tutorials on YouTube for breaking this. TUTORIALS.",
	"This cipher was deprecated for a reason. Several reasons, actually.",
	"If this cipher were a lock, it would be the one you open with a credit card.",
	"Security researchers broke this years ago and wrote papers about it. Academic papers.",
	"This is the kind of cipher that makes pentesters smile.",
	"Congratulations, you've configured the one cipher suite that actively helps attackers.",
}

var certExpiredSayings = []string{
	"The cert is EXPIRED. Dead. Gone. Pushing up digital daisies. Fix. It.",
	"Every browser on Earth is screaming at your users right now. You're welcome for the heads up.",
	"This cert has been expired longer than your gym membership.",
	"Expired. Like showing up to the airport with a passport from 2019.",
	"RIP to this cert. Nobody sent flowers. Nobody even noticed.",
	"Your users are seeing a giant scary warning page. That's on you.",
	"This cert is so dead it qualifies for archaeological study.",
	"Expired cert in production. Bold strategy. Let's see how it plays out.",
	"The cert expired and nobody renewed it. Classic 'not my job' energy.",
	"This cert has more in common with a museum exhibit than a security credential.",
}

var certExpiringSoonSayings = []string{
	"Stop reading this and go renew it. NOW. I'll wait.",
	"You're playing chicken with an expiry date. Spoiler: you lose.",
	"Days, not weeks. DAYS. Move it.",
	"If this expires on your watch, that's a resume event.",
	"This cert is on life support. Pull the renewal trigger.",
	"You have less time than you think. Cert renewals always take longer than expected.",
	"Procrastinating on this will result in a 3am outage call. Your call.",
	"This is the kind of thing that shows up in post-incident reviews with your name next to it.",
	"Calendar. Reminder. Set one. NOW.",
	"The countdown is real. Don't be the person who let the cert expire.",
}

var certExpiringSayings = []string{
	"The cert expires soon. Knowing how things work around here, nobody will renew it until it breaks.",
	"Getting close to that awkward 'who's responsible for cert renewal?' conversation.",
	"Time to start planning renewal. Or time to start updating your LinkedIn. Your choice.",
	"Not urgent yet, but 'not urgent' is how every cert outage starts.",
	"The clock is ticking. Put a reminder somewhere you'll actually see it.",
	"You've got a window. Use it. Or don't, and enjoy the outage.",
	"Still got time, but the kind of time that evaporates when you look away.",
	"This is the point where organized teams renew. Which kind of team are you?",
}

var selfSignedSayings = []string{
	"Self-signed cert. The server basically said 'trust me bro' and expects you to be cool with that.",
	"This cert signed itself. That's like writing your own reference letter.",
	"Self-signed in production is bold. Stupid bold, but bold.",
	"This wouldn't pass a security audit at a lemonade stand.",
	"No CA vouched for this cert. It's on its own out there. Alone. Unverified.",
	"A self-signed cert is like a bouncer who checks his own ID.",
	"The cert is its own witness. That's not how trust works.",
	"Self-signed certs are fine for dev. This isn't dev, is it? IS IT?",
	"Every browser on the planet will flag this with a big scary warning. On purpose.",
	"Trust me bro: Level = max. Actual trust: Level = zero.",
}

var weakKeySayings = []string{
	"This key is so weak that my grandma could brute-force it with a calculator from 1995.",
	"A key this weak is basically decorative. Like a lock made of chocolate.",
	"Modern hardware can break this key faster than you can read this sentence.",
	"This key length hasn't been acceptable since people used AOL.",
	"If this key were a password, it would be '1234'.",
	"The key is too short. That's what she said, and also what NIST said.",
	"Academic papers have been published about breaking keys this weak. PUBLISHED.",
	"A Raspberry Pi could crack this. Not even a fast one.",
}

var sha1Sayings = []string{
	"SHA-1?! Google literally created a collision attack for this in 2017. TWENTY. SEVENTEEN.",
	"Using SHA-1 in production is professional negligence. Update. The. Cert.",
	"Every major browser stopped trusting SHA-1 years ago. Where have you been?",
	"SHA-1 has been broken since 2017. That's not a secret. It was in the news.",
	"This signature algorithm is about as secure as a paper padlock.",
	"SHA-1 collisions are achievable. That means forgery is achievable. Get a new cert.",
	"Running SHA-1 is like using a fence that people can just step over.",
	"The SHAttered attack made this obsolete. Google it. Or don't, and keep being vulnerable.",
}

var hostnameMismatchSayings = []string{
	"The cert doesn't match the hostname. Someone installed the WRONG CERT.",
	"This is TLS 101, people. Read the Subject Alternative Names before installing.",
	"You connected to X, but the cert says it's Y. That's like showing up with someone else's passport.",
	"Wrong cert, wrong server, or wrong DNS. Pick your adventure.",
	"The cert was issued for a different domain. Did someone copy-paste the wrong config?",
	"Hostname mismatch. The digital equivalent of wearing someone else's name tag.",
	"Every browser will reject this immediately. Can't even blame them.",
	"The cert and the hostname aren't even close. Did anyone test this?",
	"Someone installed a cert for the wrong domain. In production. Incredible.",
	"Check the SAN list on the cert. Then check the hostname. Then facepalm.",
}

var noIssuingCASayings = []string{
	"The server didn't bother including the issuing CA. Clients everywhere are confused.",
	"No issuing CA in the response. The server just threw the leaf cert out there and hoped for the best.",
	"The issuing CA is MIA. Missing in action. Missing in the TLS handshake. Missing from this chain.",
	"You sent the leaf cert and... that's it? Where's the rest of the chain?",
	"The server's response is missing the issuing CA. Most clients will choke on this.",
	"No intermediate CA in the handshake. Half your clients can't verify this chain.",
	"The issuing CA wasn't included. It's like submitting a form with no signature — rejected.",
	"Server sent one cert. ONE. The issuing CA that signed it? Nowhere to be found.",
	"The chain starts and ends with the leaf. Where's the CA that vouched for it?",
	"Missing issuing CA. The server basically said 'figure it out yourself.' Clients can't.",
}

var missingIntermediateSayings = []string{
	"You forgot the intermediate cert. The ENTIRE chain of trust is broken.",
	"Half the browsers on earth can't verify this cert. How did this pass testing? DID you test?",
	"The chain is incomplete. It's like submitting a job application with no references.",
	"Missing intermediate = broken trust chain = angry users = angry boss.",
	"The intermediate cert is the glue between your leaf and the root. You forgot the glue.",
	"Some clients will work (they cached the intermediate). Most won't. Good luck with that.",
	"The server sent the leaf cert and just... stopped. Mid-chain. Unfinished.",
	"Without the intermediate, browsers have to GUESS. They don't guess well.",
	"The chain of trust has a gap in it. Like a bridge with a missing section.",
	"Include. The. Intermediate. It's not optional. It's literally how PKI works.",
}

var leafOnlySayings = []string{
	"The server sent ONLY the leaf cert. The issuer is an intermediate CA, not a root.",
	"Clients need both the intermediate AND root in their trust store to verify this. That's wrong.",
	"Only root CAs belong in trust stores. The intermediate should be IN the chain, not trusted separately.",
	"You're forcing every client to independently trust the intermediate CA. That defeats the whole point of PKI.",
	"The correct setup: server sends leaf + intermediate. Client trusts root. That's it. Fix it.",
	"Right now, this only works if someone manually added the intermediate to the client's trust store. Yikes.",
	"The issuing CA is NOT a root, so the chain is broken unless the client has extra certs installed.",
	"This is like giving someone directions but skipping the middle steps. 'Turn left, then... arrive.' How?",
	"Intermediate CAs exist to be SENT in the chain. Not to be trusted individually on every client machine.",
	"For this to work, every single client needs the intermediate cert installed. Every. Single. One. No.",
}

var wrongIntermediateSayings = []string{
	"Right name, wrong key. The CA was renewed but the leaf was left behind. Classic enterprise PKI.",
	"The intermediate looks correct on paper. But the signature doesn't verify. That's what matters.",
	"Someone swapped the CA without re-issuing the leaf. The name matches. The key doesn't.",
	"This is the PKI equivalent of changing the locks and not giving anyone new keys.",
	"The CA got re-keyed and nobody re-signed the leaf. The chain is broken at the most fundamental level.",
	"The issuer name matches perfectly. The cryptographic signature? Not even close.",
	"New CA key, old leaf cert. You can't just swap the intermediate and call it a day.",
	"The CA was renewed (probably re-keyed), but the leaf cert still carries the old signature. Re-issue it.",
	"This chain will fail signature verification on every client. The math doesn't lie.",
	"Close only counts in horseshoes. In PKI, the signature has to actually verify.",
}

var wrongOrderSayings = []string{
	"The chain is in the wrong order. Did someone just throw the certs into the config and hope for the best?",
	"Certificates should go: leaf → intermediate → root. Not... whatever this is.",
	"The chain is shuffled like a deck of cards. Most clients will reject this.",
	"It's like reading a book from chapter 5 to chapter 1. Technically all the pages are there, but...",
	"Chain order matters. The cert that signs the leaf should be RIGHT AFTER the leaf. Not before. Not somewhere else.",
	"TLS requires the chain to be in order. This isn't a suggestion. It's in the RFC.",
	"Some lenient clients will sort this themselves. You're betting on leniency. Bad bet.",
	"The chain order is wrong. nginx, Apache, and basically every TLS tutorial in existence explains this.",
}

var unnecessaryRootSayings = []string{
	"You're sending the root cert. Why? The client ALREADY HAS IT.",
	"The root cert is in the trust store. Sending it is just wasting bandwidth.",
	"Including the root in the chain is unnecessary. It's not harmful, but it's not smart either.",
	"The root CA doesn't need to be sent. Remove it from your chain and save some bytes.",
	"It's like mailing someone a copy of a book they already own. Technically fine, practically pointless.",
	"The root cert should NOT be in the chain. It's already trusted by the OS/browser.",
	"Extra bytes, zero benefit. The root belongs in the trust store, not in the TLS handshake.",
	"Some load balancers add this automatically. Check your config.",
	"You brought the whole family tree to a handshake. Root included. Nobody asked.",
	"The root was already invited to the trust store party. You didn't need to RSVP again.",
	"Sending the root CA is the TLS equivalent of explaining a joke after everyone already laughed.",
	"The chain works, but you're mailing your birth certificate with every letter.",
	"Technically correct — the best kind of correct. Also the most wasteful kind of correct.",
	"Full chain plus root. It's giving 'reply all to the entire company.'",
	"Your chain is valid but padded like a resume listing 'proficient in Microsoft Word.'",
	"The root cert is dead weight. Like packing a parachute for a ground-floor exit.",
}

var verificationFailedSayings = []string{
	"Verification FAILED. The trust store looked at this chain and said 'nah.'",
	"Your users are seeing a giant red warning page right now. Congrats.",
	"The system trust store does not trust this chain. At all. Zero trust. Literally.",
	"Trust store verification failed. This is the 'building is on fire' of TLS diagnostics.",
	"If you're seeing this, your users are seeing a much scarier version of this in their browser.",
	"The chain couldn't be verified. Either it's broken, expired, or using a CA nobody trusts.",
	"Failed verification means failed connections. For everyone. Fix it or accept the outage.",
	"The trust store said no. Browsers say no. Users leave. Revenue drops. Fix the chain.",
	"This chain is untrusted. Not 'kinda trusted' or 'sometimes trusted.' Untrusted. Period.",
	"Every client that tries to connect will get an error. Every. Single. One.",
}

// --- CRL Warning Checking ---

// CheckCRLWarnings examines a CRL result and generates contextual warnings.
func CheckCRLWarnings(crl analyzer.CRLResult) []analyzer.Warning {
	var w []analyzer.Warning

	if crl.IsRevoked {
		w = append(w, analyzer.Warning{
			Code:     "CRL_REVOKED",
			Severity: analyzer.WrittenInCrayon,
			Title:    "Certificate REVOKED (CRL)",
			Detail:   "The certificate's serial number appears on the CA's Certificate Revocation List.",
			Why:      pick(crlRevokedSayings),
			Explain:  "The Certificate Authority has explicitly revoked this certificate by adding its serial number to a signed CRL (Certificate Revocation List). This means the CA no longer considers this certificate valid — it could have been compromised, superseded, or decommissioned. Any client that checks revocation status (via CRL or OCSP) will reject this certificate. The cert may still appear to 'work' in some clients that don't check CRLs, but it is officially untrusted.",
			Fix:      "This certificate must be replaced. Contact your CA to reissue a new certificate, or use a new key pair if the revocation reason was Key Compromise. After reissuing, deploy the new cert and verify with: peep <host>",
			DocRef:   "peep docs crl",
		})
	}

	if crl.IsStale {
		w = append(w, analyzer.Warning{
			Code:     "CRL_STALE",
			Severity: analyzer.MallCopCredentials,
			Title:    "Stale CRL — NextUpdate Has Passed",
			Detail:   "The CRL's NextUpdate timestamp is in the past. The revocation data may be outdated.",
			Why:      pick(crlStaleSayings),
			Explain:  "The CRL's NextUpdate field indicates when a fresh CRL should have been published, and that time has passed. This means the revocation data you're relying on is outdated — if the CA revoked any certificates since the last CRL was published, those revocations won't be reflected here. Some strict clients will reject certificates when the CRL is stale. This usually indicates a CA infrastructure issue or a misconfigured CRL refresh schedule.",
			Fix:      "If this is your CA's CRL: check that the CA's CRL publishing service is running and the refresh schedule is configured correctly. If this is a public CA: the CA may be experiencing an outage — check their status page. Consider enabling OCSP stapling as a complementary revocation mechanism.",
			DocRef:   "peep docs crl",
		})
	}

	if crl.FetchError != "" {
		if isNetworkError(crl.FetchError) {
			// Network-level failure — don't penalize the server for the scanner's network path.
			w = append(w, analyzer.Warning{
				Code:     "CRL_NETWORK_ERROR",
				Severity: analyzer.MainCharacterEnergy,
				Title:    "CRL Fetch Failed (Network)",
				Detail:   "Could not reach the CRL endpoint: " + crl.FetchError + ". This may reflect the scanner's network path rather than the server's TLS configuration.",
				Why:      pick(crlNetworkErrorSayings),
				Explain:  "peep attempted to download the CRL from the certificate's CRL Distribution Point (CDP) but failed due to a network-level issue (timeout, connection refused, DNS failure, etc.). This does not necessarily mean the CRL endpoint is down — it may be unreachable from the scanner's network (VPN, firewall, air-gapped environment). The server's actual clients may have no trouble reaching the CRL endpoint from their network.",
				Fix:      "Verify the CRL endpoint is reachable from the server's perspective: curl -I <CDP-URL>. If you're scanning from a restricted network, the CRL endpoint may simply be unreachable from here.",
				DocRef:   "peep docs crl",
			})
		} else {
			w = append(w, analyzer.Warning{
				Code:     "CRL_FETCH_FAILED",
				Severity: analyzer.MallCopCredentials,
				Title:    "CRL Fetch Failed",
				Detail:   "Could not download or parse the CRL: " + crl.FetchError,
				Why:      pick(crlFetchFailedSayings),
				Explain:  "peep attempted to download the CRL from the certificate's CRL Distribution Point (CDP) but failed. Without the CRL, revocation status cannot be verified via this mechanism. The failure could be due to the CRL endpoint being down, or the CRL file being malformed. Most browsers soft-fail in this scenario (proceed without CRL checking), but this leaves a gap in revocation coverage. Critically, hard-fail clients — including Java applications (with CRL checking enabled), mTLS/mutual-TLS systems, and enterprise middleware (WebSphere, WildFly/JBoss, F5 BIG-IP) — will abort connections entirely if the CRL endpoint is unreachable. If your environment uses hard-fail revocation checking, a CRL fetch failure means a complete connection outage for all certificates issued by this CA.",
				Fix:      "Check the CRL Distribution Point URL in the certificate's extensions. Verify the URL is reachable: curl -I <CDP-URL>. If the URL is unreachable, the CA may be having an outage. If the cert has no CDP, the CA may use OCSP only — check with: peep docs ocsp. See: peep docs crl",
				DocRef:   "peep docs crl",
			})
		}
	}

	return w
}

// --- OCSP Staple Warning Checking ---

// CheckOCSPStapleWarnings examines an OCSP staple result and generates contextual warnings.
func CheckOCSPStapleWarnings(staple analyzer.OCSPStapleResult) []analyzer.Warning {
	var w []analyzer.Warning

	if staple.Status == analyzer.OCSPRevoked {
		w = append(w, analyzer.Warning{
			Code:     "OCSP_STAPLE_REVOKED",
			Severity: analyzer.WrittenInCrayon,
			Title:    "OCSP Staple Says REVOKED",
			Detail:   "The server's stapled OCSP response indicates this certificate has been revoked.",
			Why:      pick(ocspStapleRevokedSayings),
			Explain:  "The server included an OCSP staple in the TLS handshake, and that staple explicitly says the certificate is REVOKED. This is about as bad as it gets — the server is actively advertising that its own certificate is revoked. The CA has confirmed that this certificate should no longer be trusted. Clients that process the staple will immediately reject the connection. This usually happens when a cert is revoked but the server hasn't been updated with a new cert yet.",
			Fix:      "Replace this certificate immediately. The CA has revoked it — continuing to use it is pointless. Issue a new cert from your CA, deploy it, and restart the TLS service. If the revocation was due to key compromise (reason code 1), generate a new private key before requesting the new cert. Verify with: peep <host>",
			DocRef:   "peep docs ocsp",
		})
	}

	if staple.IsStale {
		if staple.HasMustStaple {
			// Must-Staple + stale staple = hard fail. Clients MUST reject.
			w = append(w, analyzer.Warning{
				Code:     "OCSP_STAPLE_STALE_MUST_STAPLE",
				Severity: analyzer.WrittenInCrayon,
				Title:    "Stale OCSP Staple on Must-Staple Certificate",
				Detail:   "The stapled OCSP response is stale AND the certificate has the Must-Staple extension. Compliant clients will reject this connection.",
				Why:      pick(ocspStapleStaleMustStapleSayings),
				Explain:  "This certificate has the OCSP Must-Staple extension (RFC 7633, OID 1.3.6.1.5.5.7.1.24), which means compliant TLS clients MUST receive a valid, fresh OCSP staple — or reject the connection entirely. The staple is present but stale (NextUpdate has passed), so it no longer counts as valid. The result is the same as having no staple at all: connection rejection. The server's OCSP staple refresh mechanism is broken.",
				Fix:      "Fix OCSP staple refresh immediately. In nginx: ensure ssl_stapling on; ssl_stapling_verify on; resolver 8.8.8.8 valid=300s; are set and the resolver is reachable. Restart nginx to force a fresh fetch. In Apache: verify SSLStaplingCache is configured and working. The staple must be refreshed before NextUpdate expires. Monitor OCSP staple freshness continuously — with Must-Staple enabled, a stale staple is an outage.",
				DocRef:   "peep docs ocsp",
			})
		} else {
			w = append(w, analyzer.Warning{
				Code:     "OCSP_STAPLE_STALE",
				Severity: analyzer.MallCopCredentials,
				Title:    "Stale OCSP Staple — NextUpdate Has Passed",
				Detail:   "The stapled OCSP response's NextUpdate is in the past. The revocation data is outdated.",
				Why:      pick(ocspStapleStaleSayings),
				Explain:  "The server included an OCSP staple, but its NextUpdate timestamp has already passed. This means the stapled revocation proof is outdated. Strict clients may reject the connection because the staple is no longer considered valid. This typically happens when the server's OCSP stapling refresh mechanism is broken — the server fetched a staple once but never refreshed it. Some web servers (like nginx) cache OCSP responses and need to be configured to refresh them before they expire.",
				Fix:      "Check your server's OCSP stapling configuration. In nginx: ssl_stapling on; ssl_stapling_verify on; and ensure the resolver directive is set. In Apache: SSLUseStapling on; SSLStaplingCache. Restart the server to force a fresh OCSP fetch. Verify the staple is fresh with: peep <host>",
				DocRef:   "peep docs ocsp",
			})
		}
	}

	if !staple.Present {
		if staple.HasMustStaple {
			// Must-Staple + no staple = hard fail. Clients MUST reject.
			w = append(w, analyzer.Warning{
				Code:     "OCSP_STAPLE_MISSING_MUST_STAPLE",
				Severity: analyzer.WrittenInCrayon,
				Title:    "Missing OCSP Staple on Must-Staple Certificate",
				Detail:   "The certificate has the Must-Staple extension but the server did not staple an OCSP response. Compliant clients will reject this connection.",
				Why:      pick(ocspStapleMissingMustStapleSayings),
				Explain:  "This certificate has the OCSP Must-Staple extension (RFC 7633, OID 1.3.6.1.5.5.7.1.24), which tells TLS clients: 'If you don't get a fresh OCSP staple in the handshake, reject the connection.' The server did not include an OCSP staple, so compliant clients (including Chrome, Firefox, and Safari) will refuse to connect. This is an outage-level misconfiguration — the cert explicitly opted into strict revocation checking but the server isn't delivering.",
				Fix:      "Enable OCSP stapling immediately. In nginx: ssl_stapling on; ssl_stapling_verify on; resolver 8.8.8.8 valid=300s;. In Apache: SSLUseStapling on; SSLStaplingCache shmcb:/tmp/stapling_cache(128000). If OCSP stapling cannot be enabled reliably, consider reissuing the certificate WITHOUT the Must-Staple extension until your stapling infrastructure is stable.",
				DocRef:   "peep docs ocsp",
			})
		} else {
			// No Must-Staple — missing staple is informational only.
			w = append(w, analyzer.Warning{
				Code:     "OCSP_STAPLE_MISSING",
				Severity: analyzer.MainCharacterEnergy,
				Title:    "No OCSP Staple Present",
				Detail:   "The server did not include a stapled OCSP response in the TLS handshake. No Must-Staple extension is present, so this is informational.",
				Why:      pick(ocspStapleMissingSayings),
				Explain:  "OCSP stapling allows the server to include a pre-fetched, CA-signed revocation status proof in the TLS handshake. Without it, clients must either (a) query the CA's OCSP responder directly — leaking which sites the user visits to the CA and adding latency, or (b) skip revocation checking entirely (soft-fail). OCSP stapling is the privacy-respecting, performance-friendly approach and is recommended for all TLS servers. Since this certificate does not have the Must-Staple extension, clients will still connect — but enabling stapling is a best practice.",
				Fix:      "Enable OCSP stapling on your server. In nginx: ssl_stapling on; ssl_stapling_verify on; resolver 8.8.8.8 valid=300s;. In Apache: SSLUseStapling on; SSLStaplingCache shmcb:/tmp/stapling_cache(128000). In HAProxy: bind ... ssl crt /path/to/cert.pem ... (HAProxy staples automatically). After enabling, verify with: peep <host>",
				DocRef:   "peep docs ocsp",
			})
		}
	}

	return w
}

// --- CRL Saying Pools ---

var crlRevokedSayings = []string{
	"This cert is on the CA's naughty list. Literally. The CRL has its serial number.",
	"Revoked. The CA said 'no.' That's it. That's the tweet.",
	"The CA revoked this cert and published the receipts. It's on the CRL for all to see.",
	"This certificate has been officially uninvited from the trust party.",
	"The CRL doesn't lie. This cert's serial number is on the list. Game over.",
	"Revoked by the CA. That's not a suggestion — it's a death sentence for this cert.",
	"This cert's serial showed up on the CRL like a name on a no-fly list.",
	"The CA pulled the plug. This cert is revoked, done, finished. Get a new one.",
}

var crlStaleSayings = []string{
	"This CRL is expired. It's like checking yesterday's news for today's weather.",
	"The CRL's NextUpdate passed. You're flying blind on revocation data.",
	"Stale CRL. The CA's revocation data is stuck in the past.",
	"This CRL hasn't been updated since NextUpdate. That's... not how freshness works.",
	"The CRL expired. Any revocations since then? Who knows! Not you.",
	"You're trusting revocation data that the CA itself says is outdated. Bold.",
	"This CRL is past its sell-by date. Would you eat expired yogurt? Same energy.",
	"NextUpdate was in the past. The CRL is stale. The data is stale. Everything is stale.",
}

var crlFetchFailedSayings = []string{
	"CRL download failed. The endpoint responded, but the data was unusable.",
	"Failed to fetch the CRL. Without it, we can't tell if this cert was revoked.",
	"The CRL endpoint returned something, but it wasn't a valid CRL. Helpful.",
	"Couldn't parse the CRL. Either the endpoint is broken or the data is corrupt.",
	"CRL fetch failed. The endpoint is up but the response isn't a CRL we can use.",
}

var crlNetworkErrorSayings = []string{
	"Couldn't reach the CRL endpoint from here. Might be our network, not theirs.",
	"CRL endpoint unreachable. Could be a firewall, could be DNS. Don't blame the server yet.",
	"Network error fetching CRL. The server's clients may have no trouble from their vantage point.",
	"CRL timeout. Before flagging the server, check if you're behind a restrictive network.",
	"Couldn't download the CRL — but that might say more about our network path than the CA's endpoint.",
	"CRL fetch timed out. This is informational — it may just be our connectivity.",
}

// --- OCSP Staple Saying Pools ---

var ocspStapleRevokedSayings = []string{
	"The server stapled an OCSP response that says REVOKED. It's broadcasting its own failure.",
	"OCSP staple says revoked. The server is literally telling everyone its cert is dead.",
	"The server attached proof of its own cert's revocation. That's a new kind of self-own.",
	"Stapled OCSP: Revoked. The server is handing out its own death certificate.",
	"The OCSP staple is a signed confession: this cert is revoked. Replace it.",
	"Server said 'here's my cert' and also 'here's proof my cert is revoked.' Pick a lane.",
	"A stapled OCSP response that says Revoked. It's like wearing a name tag that says 'FIRED.'",
	"The server included an OCSP staple. The staple says Revoked. Incredible self-report.",
}

var ocspStapleStaleSayings = []string{
	"The OCSP staple expired. The server is stapling yesterday's proof of life.",
	"Stale OCSP staple. It's like flashing an expired coupon at a bouncer.",
	"The stapled OCSP response is past NextUpdate. It's no longer proof of anything.",
	"OCSP staple is stale. The server forgot to refresh it. Classic.",
	"NextUpdate passed. This OCSP staple is as fresh as last week's sushi.",
	"The server stapled an outdated OCSP response. Points for trying, minus points for execution.",
	"Stale staple. The server cached the OCSP response and never looked back.",
	"This OCSP staple expired. It's giving 'set it and forget it' — emphasis on forget.",
}

var ocspStapleMissingSayings = []string{
	"No OCSP staple. Every client has to ask the CA directly. Hope you like latency.",
	"OCSP stapling is off. The CA now knows every visitor to this site. Privacy? Never heard of it.",
	"No staple. Clients will either query the CA (slow + privacy leak) or skip revocation checks (yikes).",
	"OCSP stapling is disabled. It's free, it's fast, it's private. Why isn't it on?",
	"No OCSP staple present. The server is making every client do the revocation homework.",
	"Missing OCSP staple. The server said 'checking revocation is YOUR problem now.'",
	"No Must-Staple, no staple. Not a deal-breaker, but stapling is always a good idea.",
	"OCSP staple? Absent. Privacy for your users? Also absent. Enable stapling.",
}

var ocspStapleMissingMustStapleSayings = []string{
	"Must-Staple is on. No staple is present. Every compliant browser is bouncing.",
	"The cert said 'you MUST staple.' The server said 'nah.' Clients said 'goodbye.'",
	"Must-Staple + no staple = guaranteed connection failures. This is an outage.",
	"RFC 7633 is very clear: Must-Staple means MUST. The server is in violation.",
	"The cert opted into strict revocation. The server didn't deliver. Game over.",
	"Must-Staple without a staple is like requiring a badge and then not checking IDs.",
	"Chrome, Firefox, Safari — all rejecting this connection right now. Must-Staple demands a staple.",
	"The certificate literally says 'staple or die.' The server chose death.",
}

var ocspStapleStaleMustStapleSayings = []string{
	"Must-Staple cert with a stale staple. Compliant clients will reject this.",
	"The staple expired but Must-Staple is still enforced. This is an active outage.",
	"Stale staple + Must-Staple = the server is serving expired proof. Clients bail.",
	"Must-Staple says 'fresh staple required.' The server's staple is past its expiry. Connection rejected.",
	"The OCSP staple is stale and the cert demands a valid one. This is a hard fail.",
	"Must-Staple + expired staple refresh = connection failures in production. Fix this now.",
}

// --- CT/SCT Warning Check ---

// CheckCTWarnings generates warnings based on Certificate Transparency results.
// When internalCA is true, the missing SCTs warning is suppressed (it's expected
// for private/internal CAs not to embed SCTs).
func CheckCTWarnings(ct analyzer.CTLogResult, internalCA bool) []analyzer.Warning {
	var w []analyzer.Warning

	if ct.IsPrivateCA || internalCA {
		// Private CA or --internal-ca mode — no warning, CT doesn't apply
		return w
	}

	if ct.Error != "" {
		w = append(w, analyzer.Warning{
			Code:     "CT_PARSE_ERROR",
			Severity: analyzer.MallCopCredentials,
			Title:    "Could Not Parse SCT Extensions",
			Detail:   "The SCT extension was present but could not be parsed: " + ct.Error,
			Why:      pick(ctParseSayings),
			Explain:  "Signed Certificate Timestamps (SCTs) are embedded in the certificate by the CA during issuance. They are cryptographic proof that the certificate was submitted to Certificate Transparency logs before it was issued. If the SCT extension is malformed, clients cannot verify CT compliance. Chrome requires at least 2 SCTs from independent logs for certificates issued by publicly-trusted CAs.",
			Fix:      "This is typically a CA-side issue — the CA embedded a malformed SCT extension. Contact your CA or re-issue the certificate. Verify the raw cert with: openssl x509 -in cert.pem -text -noout | grep -A20 'CT Precertificate'",
			DocRef:   "peep docs certs",
		})
	} else if !ct.Found {
		w = append(w, analyzer.Warning{
			Code:     "CT_NO_SCTS",
			Severity: analyzer.MallCopCredentials,
			Title:    "No Embedded SCTs Found",
			Detail:   "This certificate has no Signed Certificate Timestamps (SCTs). Missing SCTs may indicate a private/internal CA, a pre-CT certificate, or a non-compliant issuer.",
			Why:      pick(ctNoSCTSayings),
			Explain:  "Signed Certificate Timestamps (SCTs) prove a certificate was submitted to Certificate Transparency (CT) logs before issuance. Chrome, Safari, and Apple platforms require SCTs for publicly-trusted certificates. Missing embedded SCTs can mean: (1) the cert uses OCSP stapling or the TLS SCT extension instead; (2) it's issued by a private/internal CA (where CT doesn't apply — use --internal-ca); (3) it predates CT requirements; or (4) the CA is not CT-compliant. Note: peep checks for embedded SCTs only — it does not query CT logs directly.",
			Fix:      "If this is a publicly-trusted certificate, contact your CA — they should be embedding SCTs at issuance. If this is an internal/private CA, use --internal-ca to suppress this warning. Re-issuing the cert from a compliant public CA will include SCTs automatically.",
			DocRef:   "peep docs certs",
		})
	}

	return w
}

// CheckValidityPeriodWarning checks if a leaf certificate's validity period
// exceeds the CA/B Forum 398-day maximum for publicly-trusted certificates.
// Skipped when internalCA is true (internal CAs commonly issue longer-lived certs).
func CheckValidityPeriodWarning(cert analyzer.CertAnalysis, internalCA bool) []analyzer.Warning {
	var w []analyzer.Warning

	// Only check leaf certs, and only in standard (non-internal) mode
	if internalCA || cert.Role != analyzer.RoleLeaf {
		return w
	}

	if cert.ValidityDays > 398 {
		w = append(w, analyzer.Warning{
			Code:     "CERT_LONG_VALIDITY",
			Severity: analyzer.MallCopCredentials,
			Title:    fmt.Sprintf("Certificate Validity Exceeds 398 Days (%d days)", cert.ValidityDays),
			Detail:   fmt.Sprintf("This certificate has a validity period of %d days, exceeding the CA/B Forum maximum of 398 days for publicly-trusted certificates.", cert.ValidityDays),
			Why:      pick(longValiditySayings),
			Explain:  "The CA/Browser Forum Baseline Requirements cap publicly-trusted TLS certificate lifetimes at 398 days (since September 2020). Shorter lifetimes reduce the window of exposure if a private key is compromised and ensure certificates reflect current organizational ownership. Apple, Google, and Mozilla enforce this in their root programs — a publicly-trusted CA should not issue certificates exceeding this limit. If this is an internal/private CA, this limit does not apply (use --internal-ca).",
			Fix:      "Request a certificate with a validity period of 398 days or less from your CA. If this is an internal/private CA certificate, use --internal-ca to skip this check.",
			DocRef:   "peep docs certs",
		})
	}

	return w
}

var longValiditySayings = []string{
	"This cert has a validity period longer than most marriages. Shorten it.",
	"398 days is the max. This cert said 'rules are for other people.'",
	"The CA/B Forum said 398 days max. This cert apparently doesn't read memos.",
	"A cert this long-lived is a liability, not a convenience. Rotate it.",
	"This cert's validity period is so long, it'll outlive the company's next rebranding.",
	"If the key gets compromised, this cert will be the gift that keeps on giving. For attackers.",
	"Shorter cert lifetimes exist for a reason. This cert chose to ignore all of them.",
	"This cert is playing the long game. Unfortunately, so are the attackers.",
}

var ctNoSCTSayings = []string{
	"No SCTs. Chrome and Safari are going to have strong opinions about this.",
	"Zero SCTs embedded. This cert skipped the transparency queue entirely.",
	"No Certificate Transparency proof. It's like a diploma without a seal.",
	"Missing SCTs. The CA either forgot to log this cert or doesn't care about CT compliance.",
	"No SCTs found. Browsers that enforce CT will treat this cert with deep suspicion.",
	"Certificate Transparency? This cert has never heard of it.",
	"No embedded SCTs. If this were a publicly-trusted cert, browsers would be furious.",
	"SCTs: zero. Transparency: also zero. This cert is operating in stealth mode.",
}

var ctParseSayings = []string{
	"The SCT extension exists but makes no sense. That's worse than missing entirely.",
	"Malformed SCTs. Someone tried to do Certificate Transparency and failed at the binary encoding part.",
	"The SCT data is garbage. The CA's CT implementation might need a code review.",
	"SCT extension present but unparseable. It's like a signed permission slip written in crayon.",
}

// --- OCSP Live Warning Check ---

// CheckOCSPLiveWarnings generates warnings based on a live OCSP revocation check.
func CheckOCSPLiveWarnings(ocsp analyzer.OCSPResult) []analyzer.Warning {
	var w []analyzer.Warning

	switch ocsp.Status {
	case analyzer.OCSPRevoked:
		w = append(w, analyzer.Warning{
			Code:     "OCSP_REVOKED",
			Severity: analyzer.WrittenInCrayon,
			Title:    "OCSP Responder Says REVOKED",
			Detail:   fmt.Sprintf("The CA's OCSP responder confirmed this certificate is revoked. Responder: %s", ocsp.ResponderURL),
			Why:      pick(ocspLiveRevokedSayings),
			Explain:  "A live query to the CA's OCSP responder returned a REVOKED status. This is definitive — the CA has explicitly revoked this certificate. Any client that checks OCSP (stapled or live) will reject this certificate. The revocation is signed by the CA and cannot be forged. Common reasons for revocation: key compromise, CA compromise, certificate superseded, or affiliation changed.",
			Fix:      "Replace this certificate immediately. Request a new certificate from your CA, deploy it, and restart the TLS service. If the revocation was due to key compromise, generate a new private key first.",
			DocRef:   "peep docs ocsp",
		})
	case analyzer.OCSPUnknown:
		w = append(w, analyzer.Warning{
			Code:     "OCSP_UNKNOWN",
			Severity: analyzer.MallCopCredentials,
			Title:    "OCSP Responder Returned 'Unknown'",
			Detail:   fmt.Sprintf("The OCSP responder does not recognize this certificate. Responder: %s", ocsp.ResponderURL),
			Why:      pick(ocspLiveUnknownSayings),
			Explain:  "The CA's OCSP responder returned an 'Unknown' status, meaning it doesn't recognize the certificate serial number. This can happen if: (1) the OCSP responder URL doesn't match the issuing CA, (2) the cert was recently issued and the OCSP responder hasn't been updated, (3) the OCSP responder is misconfigured, or (4) the certificate was issued by a different intermediate than expected.",
			Fix:      "Verify the certificate chain is correct and the OCSP responder URL matches the issuing CA. Check the Authority Information Access (AIA) extension in the cert for the correct OCSP URL. If the cert was just issued, wait a few minutes and try again.",
			DocRef:   "peep docs ocsp",
		})
	case analyzer.OCSPError:
		if ocsp.Error != "" {
			if isNetworkError(ocsp.Error) {
				// Network-level failure — don't penalize the server for the scanner's network path.
				w = append(w, analyzer.Warning{
					Code:     "OCSP_NETWORK_ERROR",
					Severity: analyzer.MainCharacterEnergy,
					Title:    "OCSP Check Failed (Network)",
					Detail:   "Could not reach the OCSP responder: " + ocsp.Error + ". This may reflect the scanner's network path rather than the server's TLS configuration.",
					Why:      pick(ocspLiveNetworkErrorSayings),
					Explain:  "The live OCSP check failed due to a network-level issue (timeout, connection refused, DNS failure, etc.). This does not necessarily indicate a problem with the server's TLS configuration — it may reflect the scanner's network path, firewall rules, or transient connectivity issues. The server's actual clients may be able to reach the OCSP responder just fine from their network.",
					Fix:      "Verify the OCSP responder is reachable from the server's perspective: curl -v <OCSP URL>. If you're scanning from a restricted network (VPN, corporate firewall, air-gapped), the OCSP endpoint may simply be unreachable from here.",
					DocRef:   "peep docs ocsp",
				})
			} else {
				w = append(w, analyzer.Warning{
					Code:     "OCSP_ERROR",
					Severity: analyzer.MallCopCredentials,
					Title:    "OCSP Check Failed",
					Detail:   "Could not complete OCSP revocation check: " + ocsp.Error,
					Why:      pick(ocspLiveErrorSayings),
					Explain:  "The live OCSP check failed — we couldn't get a definitive answer on whether this certificate is revoked. This could be a problem with the CA's OCSP responder or a malformed response. Clients with soft-fail OCSP policies (the default in most browsers) will silently ignore this failure and trust the cert anyway. Clients with hard-fail policies will reject the connection.",
					Fix:      "Check if the OCSP responder URL is reachable: curl -v <OCSP URL>. If it's a timeout, the CA's OCSP infrastructure may be slow or down. If the URL is wrong, check the AIA extension in the certificate.",
					DocRef:   "peep docs ocsp",
				})
			}
		}
	}

	return w
}

var ocspLiveRevokedSayings = []string{
	"The CA said REVOKED. Not 'maybe revoked.' Not 'kinda revoked.' REVOKED. Full stop.",
	"OCSP returned Revoked. This cert is officially dead. The CA signed the death certificate.",
	"Revoked via OCSP. The CA pulled the plug and told the whole internet about it.",
	"The OCSP responder said no. The CA said no. Everyone says no. Replace this cert.",
	"OCSP: Revoked. That's the CA's way of saying 'we regret to inform you...'",
	"This cert is revoked. The CA's OCSP responder just confirmed it. Live. In real time.",
}

var ocspLiveUnknownSayings = []string{
	"OCSP says 'Unknown.' The CA's responder doesn't recognize this cert. That's... not great.",
	"The OCSP responder shrugged. It doesn't know this cert. Identity crisis.",
	"Unknown status from OCSP. Either the responder is misconfigured or this cert is a stranger.",
	"OCSP returned 'Unknown.' The responder and this cert have never met, apparently.",
	"The CA's OCSP responder doesn't recognize this cert. That's like your own employer not knowing you.",
}

var ocspLiveErrorSayings = []string{
	"OCSP check failed. We tried to verify revocation and the universe said 'no.'",
	"OCSP error. The CA's responder returned something unexpected.",
	"Failed to query OCSP. Soft-fail clients will shrug. Hard-fail clients will bail.",
	"The OCSP responder responded, but not in a way we can parse. Helpful.",
	"OCSP check failed — the responder said something, but it wasn't useful.",
}

var ocspLiveNetworkErrorSayings = []string{
	"Couldn't reach the OCSP responder from here. This might be a scanner-side network issue.",
	"OCSP responder unreachable. Could be our network, could be theirs. Don't panic yet.",
	"Network error reaching OCSP. The server's actual clients may have no problem.",
	"The OCSP responder didn't respond — but that might say more about our network than theirs.",
	"OCSP timeout. Before panicking, check if you're behind a firewall that blocks OCSP.",
	"Couldn't reach the OCSP endpoint. This is informational — it may just be our vantage point.",
}

// --- Cipher Enumeration Warning Check ---

// CheckCipherEnumWarnings generates warnings for insecure cipher suites found during enumeration.
func CheckCipherEnumWarnings(result analyzer.CipherEnumResult) []analyzer.Warning {
	var w []analyzer.Warning

	var insecure []string
	for _, s := range result.SupportedSuites {
		if !s.Secure {
			insecure = append(insecure, s.Name)
		}
	}

	if len(insecure) > 0 {
		detail := fmt.Sprintf("Server supports %d insecure cipher suite(s): %s", len(insecure), strings.Join(insecure, ", "))
		if len(detail) > 200 {
			detail = fmt.Sprintf("Server supports %d insecure cipher suite(s). Run 'peep scan' to see the full list.", len(insecure))
		}
		w = append(w, analyzer.Warning{
			Code:     "CIPHER_ENUM_INSECURE",
			Severity: analyzer.WrittenInCrayon,
			Title:    fmt.Sprintf("Server Accepts %d Insecure Cipher Suite(s)", len(insecure)),
			Detail:   detail,
			Why:      pick(cipherEnumInsecureSayings),
			Explain:  "The server was probed with individual cipher suites and accepted one or more that are considered insecure. Insecure ciphers include those using CBC mode (vulnerable to BEAST, Lucky13, POODLE), RC4 (biased keystream), 3DES (Sweet32 attack, 64-bit block), NULL encryption, export-grade ciphers, and suites without forward secrecy (static RSA key exchange). An attacker who can intercept traffic may be able to decrypt it using known vulnerabilities in these ciphers.",
			Fix:      "Disable insecure cipher suites in your server configuration. In nginx: ssl_ciphers 'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:!aNULL:!MD5:!DSS'; In Apache: SSLCipherSuite ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:!aNULL:!MD5. Prefer AEAD ciphers (GCM, ChaCha20-Poly1305) with ECDHE key exchange.",
			DocRef:   "peep docs ciphers",
		})
	}

	return w
}

var cipherEnumInsecureSayings = []string{
	"The server accepted insecure ciphers when asked nicely. That's the problem.",
	"Insecure ciphers are enabled. An attacker doesn't need a zero-day — just a downgrade.",
	"The server supports ciphers that were broken years ago. An archaeologist's dream.",
	"These cipher suites belong in a museum, not a production server.",
	"The server said 'yes' to ciphers it should have said 'absolutely not' to.",
	"Insecure ciphers enabled. Every vulnerability scanner on the planet is flagging this right now.",
	"The server accepts ciphers that cryptographers have been begging people to disable since 2015.",
	"These ciphers have more CVEs than features. Disable them.",
}

// --- TLS Version Probe Warning Check ---

// CheckTLSVersionProbeWarnings generates warnings for old TLS/SSL versions
// that were found to be supported during version probing.
func CheckTLSVersionProbeWarnings(result analyzer.CipherEnumResult) []analyzer.Warning {
	var w []analyzer.Warning

	for _, v := range result.TLSVersions {
		if !v.Supported {
			continue
		}
		switch v.Version {
		case "SSLv3":
			w = append(w, analyzer.Warning{
				Code:     "PROBE_SSLV3",
				Severity: analyzer.WrittenInCrayon,
				Title:    "Server Supports SSLv3",
				Detail:   "SSLv3 is enabled on this server. It was deprecated in 2015 (RFC 7568) due to the POODLE attack.",
				Why:      pick(probeSslv3Sayings),
				Explain:  "SSLv3 (from 1996) is fundamentally broken. The POODLE attack (CVE-2014-3566) allows an attacker to decrypt SSLv3 traffic by exploiting its CBC padding scheme. There is no fix — the protocol itself is flawed. RFC 7568 (June 2015) formally deprecated SSLv3 and declared it MUST NOT be used. Any server still accepting SSLv3 connections is vulnerable to downgrade attacks where a man-in-the-middle forces the client to use SSLv3 instead of TLS.",
				Fix:      "Disable SSLv3 immediately. In nginx: ssl_protocols TLSv1.2 TLSv1.3; In Apache: SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1. In OpenSSL-based configs: MinProtocol = TLSv1.2. Verify with: peep scan <host>",
				DocRef:   "peep docs tls",
			})
		case "TLSv1.0":
			w = append(w, analyzer.Warning{
				Code:     "PROBE_TLSV10",
				Severity: analyzer.WrittenInCrayon,
				Title:    "Server Supports TLS 1.0",
				Detail:   "TLS 1.0 is enabled on this server. It was deprecated in 2021 (RFC 8996).",
				Why:      pick(probeTlsOldSayings),
				Explain:  "TLS 1.0 (from 1999) has known vulnerabilities including BEAST (CVE-2011-3389) and POODLE variants. It uses a 2-round-trip handshake with weak cipher negotiation. RFC 8996 (March 2021) officially deprecated TLS 1.0 and 1.1. PCI-DSS, HIPAA, NIST SP 800-52, and FedRAMP all require TLS 1.2 or higher. All major browsers dropped TLS 1.0 support in 2020.",
				Fix:      "Disable TLS 1.0 in your server configuration. In nginx: ssl_protocols TLSv1.2 TLSv1.3; In Apache: SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1. Minimum: TLS 1.2. Preferred: TLS 1.3.",
				DocRef:   "peep docs tls",
			})
		case "TLSv1.1":
			w = append(w, analyzer.Warning{
				Code:     "PROBE_TLSV11",
				Severity: analyzer.WrittenInCrayon,
				Title:    "Server Supports TLS 1.1",
				Detail:   "TLS 1.1 is enabled on this server. It was deprecated in 2021 (RFC 8996).",
				Why:      pick(probeTlsOldSayings),
				Explain:  "TLS 1.1 (from 2006) was deprecated alongside TLS 1.0 by RFC 8996 (March 2021). While slightly better than 1.0, it still lacks AEAD ciphers, has a slower 2-round-trip handshake, and is no longer considered secure. All major compliance frameworks require TLS 1.2 minimum.",
				Fix:      "Disable TLS 1.1 in your server configuration. In nginx: ssl_protocols TLSv1.2 TLSv1.3; In Apache: SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1. Verify with: peep scan <host>",
				DocRef:   "peep docs tls",
			})
		}
	}

	return w
}

var probeSslv3Sayings = []string{
	"SSLv3 is from 1996. It was broken in 2014. That's a decade of 'please disable this.'",
	"SSLv3 enabled. POODLE says thanks for the easy target.",
	"This server still speaks SSLv3. The '90s called — they want their protocol back.",
	"SSLv3 was deprecated by RFC 7568 in 2015. Ten years ago. TEN.",
	"POODLE (CVE-2014-3566) killed SSLv3. Why is the corpse still answering handshakes?",
	"SSLv3 is enabled. Every security scanner on the planet is flagging this.",
}

var probeTlsOldSayings = []string{
	"This version was deprecated by RFC 8996 in 2021. Yet here it is, still answering calls.",
	"Deprecated. Browsers dropped it. Compliance frameworks banned it. Your server still supports it.",
	"This TLS version is so old it can legally buy alcohol in most countries.",
	"RFC 8996 said MUST NOT USE. Your server said 'watch me.'",
	"Every major browser removed this version in 2020. Your server didn't get the memo.",
	"PCI-DSS, HIPAA, NIST, and FedRAMP all say no. Your server says yes. Somebody's wrong.",
	"This version is a downgrade attack waiting to happen. Disable it.",
	"Deprecated in 2021. Browsers killed it in 2020. Your server is running a zombie protocol.",
}

