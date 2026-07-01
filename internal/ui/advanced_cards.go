package ui

import (
	"fmt"
	"strings"

	"github.com/thexsa/peep/internal/analyzer"
)

// RenderOCSPResult renders the OCSP check result.
func RenderOCSPResult(result analyzer.OCSPResult) string {
	header := Theme.BoldStyle.Render("OCSP REVOCATION CHECK")

	var lines []string
	lines = append(lines, header)
	lines = append(lines, "")

	switch result.Status {
	case analyzer.OCSPGood:
		lines = append(lines, renderKV("Status", Theme.SuccessStyle.Render("Good — not revoked")))
		lines = append(lines, renderKV("", Theme.MutedStyle.Render(PickSass(ocspGoodSayings))))
	case analyzer.OCSPRevoked:
		lines = append(lines, renderKV("Status", Theme.ErrorStyle.Render("REVOKED")))
		if !result.RevokedAt.IsZero() {
			lines = append(lines, renderKV("Revoked At", result.RevokedAt.Format("Jan 02, 2006 15:04:05 MST")))
		}
		if result.RevokeReason != "" {
			lines = append(lines, renderKV("Reason", result.RevokeReason))
		}
	case analyzer.OCSPUnknown:
		lines = append(lines, renderKV("Status", Theme.WarningStyle.Render("Unknown")))
	case analyzer.OCSPError:
		lines = append(lines, renderKV("Status", Theme.WarningStyle.Render("Error checking")))
	}

	if result.Error != "" && result.Status != analyzer.OCSPGood {
		lines = append(lines, renderKV("Detail", Theme.MutedStyle.Render(result.Error)))
	}

	if result.ResponderURL != "" {
		lines = append(lines, renderKV("Responder", Theme.MutedStyle.Render(result.ResponderURL)))
	}

	if !result.ThisUpdate.IsZero() {
		lines = append(lines, renderKV("Last Check", result.ThisUpdate.Format("Jan 02, 2006 15:04:05 MST")))
	}
	if !result.NextUpdate.IsZero() {
		lines = append(lines, renderKV("Next Update", result.NextUpdate.Format("Jan 02, 2006 15:04:05 MST")))
	}

	return ApplyBorder(lines, SectionBorder) + "\n"
}

// RenderOCSPStapleResult renders the stapled OCSP response check.
func RenderOCSPStapleResult(result analyzer.OCSPStapleResult) string {
	header := Theme.BoldStyle.Render("OCSP STAPLE CHECK")

	var lines []string
	lines = append(lines, header)
	lines = append(lines, "")

	if !result.Present {
		lines = append(lines, renderKV("Stapled", Theme.WarningStyle.Render("No — server did not staple an OCSP response")))
		lines = append(lines, renderKV("", Theme.MutedStyle.Render(PickSass(ocspStapleAbsentSayings))))
		return ApplyBorder(lines, SectionBorder) + "\n"
	}

	lines = append(lines, renderKV("Stapled", Theme.SuccessStyle.Render("Yes")))

	switch result.Status {
	case analyzer.OCSPGood:
		lines = append(lines, renderKV("Status", Theme.SuccessStyle.Render("Good — certificate is valid")))
	case analyzer.OCSPRevoked:
		lines = append(lines, renderKV("Status", Theme.ErrorStyle.Render("REVOKED — stapled response says cert is revoked!")))
	case analyzer.OCSPUnknown:
		lines = append(lines, renderKV("Status", Theme.WarningStyle.Render("Unknown")))
	case analyzer.OCSPError:
		lines = append(lines, renderKV("Status", Theme.WarningStyle.Render("Error parsing staple")))
		if result.Error != "" {
			lines = append(lines, renderKV("Detail", Theme.MutedStyle.Render(result.Error)))
		}
	}

	if !result.ProducedAt.IsZero() {
		lines = append(lines, renderKV("Produced At", result.ProducedAt.Format("Jan 02, 2006 15:04:05 MST")))
	}
	if !result.ThisUpdate.IsZero() {
		lines = append(lines, renderKV("This Update", result.ThisUpdate.Format("Jan 02, 2006 15:04:05 MST")))
	}
	if !result.NextUpdate.IsZero() {
		label := "Next Update"
		value := result.NextUpdate.Format("Jan 02, 2006 15:04:05 MST")
		if result.IsStale {
			value += Theme.ErrorStyle.Render(" (STALE — past due!)")
		}
		lines = append(lines, renderKV(label, value))
	}

	return ApplyBorder(lines, SectionBorder) + "\n"
}

// RenderCRLResult renders the CRL revocation check result.
func RenderCRLResult(result analyzer.CRLResult) string {
	header := Theme.BoldStyle.Render("CRL REVOCATION CHECK")

	var lines []string
	lines = append(lines, header)
	lines = append(lines, "")

	if !result.Available {
		lines = append(lines, renderKV("Status", Theme.MutedStyle.Render("No CRL distribution points in certificate")))
		return ApplyBorder(lines, SectionBorder) + "\n"
	}

	lines = append(lines, renderKV("CRL Endpoint", Theme.MutedStyle.Render(result.CRLEndpoint)))

	if !result.Fetched {
		lines = append(lines, renderKV("Fetch", Theme.WarningStyle.Render("Failed")))
		if result.FetchError != "" {
			lines = append(lines, renderKV("Detail", Theme.MutedStyle.Render(result.FetchError)))
		}
		lines = append(lines, renderKV("", Theme.MutedStyle.Render(PickSass(crlFetchFailSayings))))
		return ApplyBorder(lines, SectionBorder) + "\n"
	}

	lines = append(lines, renderKV("Fetch", Theme.SuccessStyle.Render(fmt.Sprintf("OK (%d bytes, %d entries)", result.CRLSize, result.EntryCount))))

	if result.IsRevoked {
		lines = append(lines, renderKV("Status", Theme.ErrorStyle.Render("REVOKED — certificate found on CRL!")))
		if !result.RevokedAt.IsZero() {
			lines = append(lines, renderKV("Revoked At", result.RevokedAt.Format("Jan 02, 2006 15:04:05 MST")))
		}
		if result.RevokeReason != "" {
			lines = append(lines, renderKV("Reason", result.RevokeReason))
		}
	} else {
		lines = append(lines, renderKV("Status", Theme.SuccessStyle.Render("Not revoked — serial not found on CRL")))
	}

	if !result.ThisUpdate.IsZero() {
		lines = append(lines, renderKV("Published", result.ThisUpdate.Format("Jan 02, 2006 15:04:05 MST")))
	}
	if !result.NextUpdate.IsZero() {
		value := result.NextUpdate.Format("Jan 02, 2006 15:04:05 MST")
		if result.IsStale {
			value += Theme.ErrorStyle.Render(" (STALE — past due!)")
		}
		lines = append(lines, renderKV("Next Update", value))
	}

	return ApplyBorder(lines, SectionBorder) + "\n"
}

// RenderCTLogResult renders the Certificate Transparency log check.
func RenderCTLogResult(result analyzer.CTLogResult) string {
	header := Theme.BoldStyle.Render("CERTIFICATE TRANSPARENCY")

	var lines []string
	lines = append(lines, header)
	lines = append(lines, "")

	if result.Error != "" {
		lines = append(lines, renderKV("Status", Theme.WarningStyle.Render("Could not check CT logs")))
		lines = append(lines, renderKV("Detail", Theme.MutedStyle.Render(result.Error)))
	} else if result.Found {
		lines = append(lines, renderKV("Status", Theme.SuccessStyle.Render("Found in CT logs")))
		lines = append(lines, renderKV("Entries", fmt.Sprintf("%d log entries found", result.LogCount)))
		if result.FirstSeen != "" {
			lines = append(lines, renderKV("First Seen", result.FirstSeen))
		}
	} else {
		lines = append(lines, renderKV("Status", Theme.WarningStyle.Render("Not in CT logs")))
		lines = append(lines, renderKV("", Theme.MutedStyle.Render(PickSass(ctNotFoundSayings))))
	}

	return ApplyBorder(lines, SectionBorder) + "\n"
}

// --- Cipher sass pools ---

// cipherSass returns a unique-per-render sarcastic annotation for insecure ciphers.
func cipherSass(name string) string {
	upper := strings.ToUpper(name)
	switch {
	case strings.Contains(upper, "NULL"):
		return PickSass(cipherNullSayings)
	case strings.Contains(upper, "EXPORT"):
		return PickSass(cipherExportSayings)
	case strings.Contains(upper, "RC4"):
		return PickSass(cipherRC4Sayings)
	case strings.Contains(upper, "DES_CBC3") || strings.Contains(upper, "3DES"):
		return PickSass(cipher3DESSayings)
	case strings.Contains(upper, "DES"):
		return PickSass(cipherDESSayings)
	case strings.Contains(upper, "ANON") || strings.Contains(upper, "ADH") || strings.Contains(upper, "AECDH"):
		return PickSass(cipherAnonSayings)
	case strings.Contains(upper, "CBC"):
		return PickSass(cipherCBCSayings)
	// RSA key exchange (no ECDHE/DHE) = no forward secrecy
	case strings.HasPrefix(upper, "TLS_RSA_"):
		return PickSass(cipherRSAKexSayings)
	default:
		return ""
	}
}

var cipherNullSayings = []string{
	"← literally no encryption. Impressive commitment to insecurity.",
	"← NULL cipher. You're sending plaintext and calling it TLS. Bold move.",
	"← congratulations, you've achieved the cryptographic equivalent of shouting across the room.",
	"← this cipher does nothing. It's the participation trophy of encryption.",
	"← NULL means zero. As in zero security. As in why does this exist.",
	"← you'd get the same protection writing your password on a postcard.",
}

var cipherExportSayings = []string{
	"← designed to be breakable by '90s governments. Now breakable by everyone.",
	"← EXPORT-grade: intentionally weakened for compliance with laws that expired decades ago.",
	"← this cipher exists because the NSA asked nicely in 1992. It's 2026. Move on.",
	"← FREAK and Logjam called. They said thanks for leaving this enabled.",
	"← EXPORT: for when 40-bit keys seemed 'secure enough' for non-Americans.",
	"← the digital equivalent of a lock you can open with a credit card.",
}

var cipherRC4Sayings = []string{
	"← broken since 2013, still lurking in configs like a cockroach.",
	"← RC4: the cipher that keeps showing up to parties it wasn't invited to.",
	"← RFC 7465 said 'stop using RC4.' That was 2015. Take the hint.",
	"← statistically biased, practically broken, yet somehow still here.",
	"← RC4 is to cryptography what asbestos is to insulation. Technically works. Terrible idea.",
	"← if your threat model includes 'nobody will bother attacking us,' RC4 is perfect.",
}

var cipher3DESSayings = []string{
	"← grandma's cipher. Sweet32 says hi.",
	"← 3DES: because running a broken cipher three times makes it... still broken.",
	"← Sweet32 can recover plaintext after 32GB of data. Your average video call generates that.",
	"← three rounds of DES in a trenchcoat pretending to be secure.",
	"← deprecated by NIST in 2024. They were being generous with the timeline.",
	"← slower than AES AND less secure. The worst of both worlds.",
}

var cipherDESSayings = []string{
	"← 56-bit key. Crackable before your coffee gets cold.",
	"← DES was broken by a $250K machine in 1998. Your laptop is faster now.",
	"← 56 bits of security. A modern GPU cracks this during its lunch break.",
	"← the EFF built a DES cracker for $250K in 1998. It's free on AWS now.",
	"← single DES in production is a cry for help.",
	"← this cipher was retired before most interns were born.",
}

var cipherAnonSayings = []string{
	"← anonymous key exchange = no authentication = no security.",
	"← anonymous cipher: anyone can MITM this and you'd never know.",
	"← no authentication means no way to know if you're talking to the real server or an imposter.",
	"← anonymous key exchange is like checking ID by asking 'are you over 21?' and trusting the answer.",
	"← ADH/AECDH: for when you want encryption without any of that pesky 'knowing who you're talking to.'",
	"← congratulations, you've encrypted your connection to... someone. Could be anyone, really.",
}

var cipherCBCSayings = []string{
	"← BEAST, Lucky13, and POODLE walk into a bar. This cipher was already there.",
	"← CBC mode: a padding oracle's best friend since 2002.",
	"← the 'C' in CBC stands for 'Come exploit me.'",
	"← padding oracles have entered the chat. CBC mode has left the chat.",
	"← CBC in TLS has more CVEs than a Windows XP box connected to the internet.",
	"← every few years someone finds a new way to break CBC. It's basically a tradition at this point.",
	"← AEAD ciphers exist. Use them. CBC is the 'flip phone' of cipher modes.",
	"← if CBC were a car, it would be on its fifth recall.",
}

var cipherRSAKexSayings = []string{
	"← RSA key exchange: no forward secrecy. Compromise the key, decrypt ALL past traffic.",
	"← static RSA: one leaked private key and every recorded session is now readable. Forever.",
	"← no forward secrecy. The NSA is taking notes. Literally.",
	"← ECDHE exists. Use it. RSA key exchange is a time bomb.",
	"← without forward secrecy, your traffic is one key compromise away from being an open book.",
	"← RSA key exchange: because who needs forward secrecy when you can live dangerously?",
	"← if someone records this traffic and later gets the private key, it's game over. ECDHE prevents that.",
	"← PFS-free zone. Hope nobody is recording your traffic. (Spoiler: they are.)",
}

// --- TLS version sass ---

// tlsVersionSass returns a sarcastic annotation for deprecated TLS versions.
func tlsVersionSass(version string) string {
	switch version {
	case "TLS 1.0":
		return PickSass(tls10Sayings)
	case "TLS 1.1":
		return PickSass(tls11Sayings)
	case "SSL 3.0":
		return PickSass(ssl30Sayings)
	default:
		return ""
	}
}

var tls10Sayings = []string{
	"← deprecated before TikTok existed",
	"← PCI DSS banned this in 2018. You're late.",
	"← every major browser dropped TLS 1.0 support. Take the hint.",
	"← this version is old enough to vote.",
}

var tls11Sayings = []string{
	"← nobody threw a funeral, but it's dead",
	"← TLS 1.1: the version nobody remembers existed.",
	"← deprecated in RFC 8996 (2021). Not even a controversial decision.",
	"← the forgotten middle child of TLS versions.",
}

var ssl30Sayings = []string{
	"← POODLE ate this alive in 2014",
	"← SSL 3.0 in production is a compliance violation in most frameworks.",
	"← this protocol is older than some of your coworkers.",
	"← if you're still supporting SSL 3.0, we need to have a serious conversation.",
}

// --- OCSP / CRL / CT sass pools ---

var ocspGoodSayings = []string{
	"The CA says this cert is legit. For now.",
	"Clean bill of health. Don't let it go to your head.",
	"Not revoked. That's the bare minimum, but sure, celebrate.",
	"OCSP says 'good.' Enjoy it while it lasts.",
	"The CA hasn't disowned this cert yet. Progress.",
	"All clear on the revocation front. One less thing to worry about.",
	"Valid according to the CA. They've been known to be right occasionally.",
	"OCSP check passed. Your cert lives to serve another day.",
}

var ocspStapleAbsentSayings = []string{
	"Every client now has to ask the CA directly. Hope they enjoy the latency.",
	"Without stapling, the CA sees every visitor. Privacy? Never heard of it.",
	"Your server had one job: staple the OCSP response. It chose not to.",
	"No staple means every client does its own OCSP lookup. Or just skips it. Both are bad.",
	"The server equivalent of 'I'll bring the dessert' and showing up empty-handed.",
	"OCSP stapling is free, fast, and privacy-preserving. So naturally, it's not enabled.",
	"Clients will soft-fail and skip the check. Congrats, you've made revocation optional.",
	"Must-Staple extension + no staple = every strict client bounces. Check your extensions.",
}

var crlFetchFailSayings = []string{
	"Can't check what you can't reach. The CRL endpoint is MIA.",
	"The CRL endpoint said 'no.' Or maybe it said nothing at all.",
	"CRL fetch failed. Revocation status: ¯\\_(ツ)_/¯",
	"Couldn't download the CRL. Either the endpoint is down or it's using a protocol from 1997.",
	"CRL unreachable. If the cert IS revoked, we'd never know. Sleep well.",
	"The revocation list is behind a door we can't open. Super reassuring.",
	"LDAP CRL endpoints: because HTTP was too easy and too functional.",
	"Failed to fetch the CRL. This is the 'check engine light' of PKI.",
}

var ctNotFoundSayings = []string{
	"Either brand new or someone's hiding something. Both are interesting.",
	"Not in CT logs. Freshly minted or intentionally invisible. Your call.",
	"No CT log entries. Could be a brand-new cert, could be a rogue cert. Fun guessing game.",
	"CT logs have no record of this cert. It's either very new or very suspicious.",
	"Absent from Certificate Transparency. Like a ghost. A potentially untrustworthy ghost.",
	"CT logs: 'never seen this cert before.' Make of that what you will.",
	"Not logged in CT. Chrome and Safari might have opinions about this.",
	"Zero CT log entries. If this cert is older than 24 hours, that's a red flag.",
}

// --- Unnecessary root sass pool ---

var unnecessaryRootSayings = []string{
	"The root is already in the trust store. You're just wasting bandwidth.",
	"The trust store has the root. You're just FedExing what's already in the filing cabinet.",
	"Sending the root CA is like bringing your own toilet to a hotel. It's already there.",
	"The root cert is dead weight in the handshake. Every byte counts on high-traffic servers.",
	"Root CA in the chain: technically harmless, practically pointless.",
	"You brought the whole family tree to a handshake. Nobody asked for the root.",
	"Sending the root CA is the TLS equivalent of explaining a joke after everyone already laughed.",
	"Full chain plus root. It's giving 'reply all to the entire company.'",
	"Your chain is valid but padded like a resume listing 'proficient in Microsoft Word.'",
	"The root cert won't help clients that don't already trust it. That's not how trust stores work.",
}

// RenderCipherEnum renders the cipher suite enumeration results.
func RenderCipherEnum(result analyzer.CipherEnumResult) string {
	header := Theme.BoldStyle.Render("SUPPORTED CIPHER SUITES & TLS VERSIONS")

	var lines []string
	lines = append(lines, header)
	lines = append(lines, "")

	// TLS Version support
	lines = append(lines, Theme.BoldStyle.Render("TLS Versions:"))
	for _, v := range result.TLSVersions {
		if !v.Supported {
			lines = append(lines, fmt.Sprintf("  %-10s %s", v.Version, Theme.MutedStyle.Render("not supported")))
			continue
		}
		icon := StatusIcon(v.Grade)
		sass := tlsVersionSass(v.Version)
		if sass != "" {
			lines = append(lines, fmt.Sprintf("  %-10s %s  %s", v.Version, icon, Theme.ErrorStyle.Render(sass)))
		} else {
			lines = append(lines, fmt.Sprintf("  %-10s %s", v.Version, icon))
		}
	}

	// Cipher suites
	lines = append(lines, "")
	lines = append(lines, Theme.BoldStyle.Render(fmt.Sprintf("Cipher Suites (%d supported):", len(result.SupportedSuites))))

	// Group by grade
	var bad, good []analyzer.CipherSuiteInfo
	for _, suite := range result.SupportedSuites {
		if suite.Grade == analyzer.WrittenInCrayon {
			bad = append(bad, suite)
		} else {
			good = append(good, suite)
		}
	}

	if len(bad) > 0 {
		lines = append(lines, "")
		lines = append(lines, Theme.ErrorStyle.Render(fmt.Sprintf("  Insecure (%d):", len(bad))))
		for _, suite := range bad {
			sass := cipherSass(suite.Name)
			if sass != "" {
				lines = append(lines, fmt.Sprintf("    %s %s  %s",
					Theme.ErrorStyle.Render("x"),
					Theme.MutedStyle.Render(suite.Name),
					Theme.ErrorStyle.Render(sass)))
			} else {
				lines = append(lines, fmt.Sprintf("    %s %s",
					Theme.ErrorStyle.Render("x"),
					Theme.MutedStyle.Render(suite.Name)))
			}
		}
	}

	if len(good) > 0 {
		lines = append(lines, "")
		lines = append(lines, Theme.SuccessStyle.Render(fmt.Sprintf("  Secure (%d):", len(good))))
		for _, suite := range good {
			lines = append(lines, fmt.Sprintf("    %s %s [%s]",
				Theme.SuccessStyle.Render("+"),
				suite.Name,
				Theme.MutedStyle.Render(suite.Version)))
		}
	}

	if len(result.SupportedSuites) == 0 {
		lines = append(lines, Theme.MutedStyle.Render("  No cipher suites detected"))
	}

	// Summary
	lines = append(lines, "")
	if len(bad) > 0 {
		lines = append(lines, Theme.ErrorStyle.Render(fmt.Sprintf("%d insecure cipher suite(s) detected. Disable them. Yesterday.", len(bad))))
	} else if len(good) > 0 {
		lines = append(lines, Theme.SuccessStyle.Render("All supported cipher suites are secure."))
	}

	return ApplyBorder(lines, SectionBorder) + "\n"
}
