package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
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

	// Show LDAP-only case
	if result.IsLDAP {
		lines = append(lines, renderKV("CRL Endpoint", Theme.MutedStyle.Render(truncateURI(result.LDAPEndpoint, 80))))
		lines = append(lines, renderKV("Protocol", Theme.WarningStyle.Render("LDAP (cannot fetch via HTTP)")))
		lines = append(lines, renderKV("", Theme.MutedStyle.Render(
			"This is a Microsoft AD CS CRL distributed via LDAP/Active Directory.")))
		lines = append(lines, renderKV("", Theme.MutedStyle.Render(
			"To check manually from a domain-joined machine:")))
		lines = append(lines, renderKV("", Theme.MutedStyle.Render(
			"  "+analyzer.LDAPSearchCommand(result.LDAPEndpoint))))
		lines = append(lines, renderKV("", Theme.MutedStyle.Render(PickSass(crlFetchFailSayings))))
		return ApplyBorder(lines, SectionBorder) + "\n"
	}

	lines = append(lines, renderKV("CRL Endpoint", Theme.MutedStyle.Render(result.CRLEndpoint)))

	if !result.Fetched {
		lines = append(lines, renderKV("Fetch", Theme.WarningStyle.Render("Failed")))
		if result.FetchError != "" {
			lines = append(lines, renderKV("Detail", Theme.MutedStyle.Render(result.FetchError)))
		}
		lines = append(lines, renderKV("", Theme.MutedStyle.Render(PickSass(crlFetchFailSayings))))
		// Note skipped LDAP endpoints
		if len(result.SkippedLDAP) > 0 {
			lines = append(lines, "")
			lines = append(lines, renderKV("LDAP CRL", Theme.MutedStyle.Render("Also available via LDAP (not fetchable):")))
			lines = append(lines, renderKV("", Theme.MutedStyle.Render(
				"  "+analyzer.LDAPSearchCommand(result.SkippedLDAP[0]))))
		}
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

	// TLS warning for HTTPS CRL endpoints with cert issues
	if result.TLSWarning != "" {
		lines = append(lines, "")
		lines = append(lines, renderKV("", Theme.WarningStyle.Render("[WARN] "+result.TLSWarning)))
	}

	// Note skipped LDAP endpoints if we used an HTTP fallback
	if len(result.SkippedLDAP) > 0 {
		lines = append(lines, "")
		lines = append(lines, renderKV("Note", Theme.MutedStyle.Render("LDAP CRL also available (skipped — used HTTP endpoint instead)")))
	}

	return ApplyBorder(lines, SectionBorder) + "\n"
}

// RenderCTLogResult renders the Certificate Transparency log check.
func RenderCTLogResult(result analyzer.CTLogResult, internalCA bool) string {
	header := Theme.BoldStyle.Render("CERTIFICATE TRANSPARENCY")

	var lines []string
	lines = append(lines, header)
	lines = append(lines, "")

	if result.Error != "" {
		lines = append(lines, renderKV("Status", Theme.WarningStyle.Render("Could not parse SCTs")))
		lines = append(lines, renderKV("Detail", Theme.MutedStyle.Render(result.Error)))
	} else if result.Found {
		lines = append(lines, renderKV("Status", Theme.SuccessStyle.Render(fmt.Sprintf(
			"Certificate has %d embedded SCT(s)", len(result.SCTs)))))
		lines = append(lines, "")
		for i, sct := range result.SCTs {
			logName := sct.LogName
			if logName == "" {
				logName = fmt.Sprintf("Unknown log (%s…)", sct.LogID[:16])
			}
			ts := sct.Timestamp.Format("Jan 02, 2006 15:04:05 MST")
			lines = append(lines, renderKV(
				fmt.Sprintf("  SCT #%d", i+1),
				fmt.Sprintf("%s  %s", Theme.SuccessStyle.Render("✓ "+logName), Theme.MutedStyle.Render(ts))))
		}
	} else if result.IsPrivateCA || internalCA {
		lines = append(lines, renderKV("Status", Theme.MutedStyle.Render("No embedded SCTs (expected for internal CA)")))
		lines = append(lines, renderKV("", Theme.MutedStyle.Render(PickSass(ctPrivateCASayings))))
	} else {
		lines = append(lines, renderKV("Status", Theme.WarningStyle.Render("No embedded SCTs")))
		lines = append(lines, renderKV("Note", Theme.MutedStyle.Render("SCTs may be delivered via OCSP stapling or TLS extension instead")))
		lines = append(lines, renderKV("", Theme.MutedStyle.Render(PickSass(ctNotFoundSayings))))
	}

	return ApplyBorder(lines, SectionBorder) + "\n"
}

// RenderCAOriginEvidence renders the CA origin confidence scoring results.
// Only shown in standard mode (not when --internal-ca is passed).
func RenderCAOriginEvidence(result analyzer.CAOriginResult) string {
	header := Theme.BoldStyle.Render("CA ORIGIN ASSESSMENT")

	var lines []string
	lines = append(lines, header)
	lines = append(lines, "")

	// Assessment with color
	purpleStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#C084FC"))
	assessStyle := Theme.MutedStyle.Render
	switch result.Assessment {
	case "public_ca":
		assessStyle = Theme.SuccessStyle.Render
	case "very_likely_private_ca", "likely_private_ca":
		assessStyle = purpleStyle.Render
	case "possibly_private_ca":
		assessStyle = purpleStyle.Render
	}

	label := formatAssessment(result.Assessment)
	lines = append(lines, renderKV("Assessment", assessStyle(fmt.Sprintf("%s (score: %d)", label, result.Score))))

	if len(result.Evidence) > 0 {
		lines = append(lines, "")
		lines = append(lines, renderKV("Evidence", ""))
		for _, e := range result.Evidence {
			sign := "+"
			if e.Points < 0 {
				sign = ""
			}
			pointStr := fmt.Sprintf("[%s%d]", sign, e.Points)
			lines = append(lines, renderKV("", fmt.Sprintf("  %s  %s", Theme.BoldStyle.Render(fmt.Sprintf("%-6s", pointStr)), e.Detail)))
		}
	}

	// Sassy comment based on assessment
	switch result.Assessment {
	case "very_likely_private_ca", "likely_private_ca":
		lines = append(lines, "")
		lines = append(lines, renderKV("", Theme.MutedStyle.Render(PickSass(caOriginPrivateSayings))))
	case "possibly_private_ca":
		lines = append(lines, "")
		lines = append(lines, renderKV("", Theme.MutedStyle.Render(PickSass(caOriginMaybeSayings))))
	}

	return ApplyBorder(lines, SectionBorder) + "\n"
}

func formatAssessment(assessment string) string {
	switch assessment {
	case "public_ca":
		return "Public CA"
	case "very_likely_private_ca":
		return "Very likely private/internal CA"
	case "likely_private_ca":
		return "Likely private/internal CA"
	case "possibly_private_ca":
		return "Possibly private/internal CA"
	default:
		return "Unknown"
	}
}

var caOriginPrivateSayings = []string{
	"This cert has 'internal infrastructure' written all over it. Use --internal-ca for appropriate grading.",
	"The evidence strongly suggests a private CA. If that's expected, --internal-ca is your friend.",
	"Everything about this cert screams 'enterprise PKI.' Consider --internal-ca for a fairer grade.",
	"This looks like an internal CA cert doing internal CA things. Use --internal-ca to adjust the rubric.",
	"Private CA detected. Nothing wrong with that — just use --internal-ca so peep grades it fairly.",
	"The fingerprints are all over this one — internal CA. Use --internal-ca to silence the public-CA-only checks.",
}

var caOriginMaybeSayings = []string{
	"Could be a private CA, could be a misconfigured public one. --internal-ca if you know for sure.",
	"The evidence is mixed. If you know this is an internal CA, tell peep with --internal-ca.",
	"Hard to say definitively. If this is an enterprise cert, --internal-ca will adjust the grading.",
	"Inconclusive origin. Use --internal-ca if you know the CA, or investigate the chain.",
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

// tlsVersionSass returns a sarcastic annotation for TLS versions in the
// cipher enumeration output. Provides commentary for both supported and
// not-supported versions.
func tlsVersionSass(version string, supported bool) string {
	if !supported {
		switch version {
		case "SSLv3":
			return PickSass(ssl30NotSupportedSayings)
		case "TLSv1.0":
			return PickSass(tls10NotSupportedSayings)
		case "TLSv1.1":
			return PickSass(tls11NotSupportedSayings)
		default:
			return ""
		}
	}
	switch version {
	case "TLSv1.0":
		return PickSass(tls10Sayings)
	case "TLSv1.1":
		return PickSass(tls11Sayings)
	case "SSLv3":
		return PickSass(ssl30Sayings)
	case "TLSv1.2":
		return PickSass(tls12Sayings)
	case "TLSv1.3":
		return PickSass(tls13Sayings)
	default:
		return ""
	}
}

var tls10Sayings = []string{
	"← deprecated before TikTok existed",
	"← PCI DSS banned this in 2018. You're late.",
	"← every major browser dropped TLS 1.0 support. Take the hint.",
	"← this version is old enough to vote.",
	"← RFC 8996 says this is dead. Who are you arguing with?",
	"← BEAST, Lucky13, and friends all live here. It's a party you don't want to attend.",
	"← congratulations, you're backward-compatible with 1999.",
	"← supporting TLS 1.0 is like leaving the back door unlocked 'for convenience.'",
	"← your compliance auditor just felt a disturbance in the Force.",
	"← this protocol has been on life support longer than most sitcoms.",
	"← if your users need TLS 1.0, they also need new devices.",
	"← still here? This should've been disabled during the Obama administration.",
}

var tls11Sayings = []string{
	"← nobody threw a funeral, but it's dead",
	"← TLS 1.1: the version nobody remembers existed.",
	"← deprecated in RFC 8996 (2021). Not even a controversial decision.",
	"← the forgotten middle child of TLS versions.",
	"← exists purely so people can say 'we support more than one version.'",
	"← TLS 1.1 is the New Year's resolution of protocols — full of good intentions, ultimately abandoned.",
	"← it fixed BEAST and then immediately became irrelevant.",
	"← TLS 1.1: too broken to be modern, too new to be nostalgic.",
	"← the protocol equivalent of a participation trophy.",
	"← removed from every major browser by 2020. You're on borrowed time.",
	"← literally nobody is negotiating this version on purpose.",
	"← disable this and literally zero legitimate users will notice.",
}

var ssl30Sayings = []string{
	"← POODLE ate this alive in 2014",
	"← SSL 3.0 in production is a compliance violation in most frameworks.",
	"← this protocol is older than some of your coworkers.",
	"← if you're still supporting SSL 3.0, we need to have a serious conversation.",
	"← SSL 3.0 was designed when 'security' meant a padlock GIF on the page.",
	"← this belongs in a museum, not a server config.",
	"← Netscape Navigator called. Even it thinks you should upgrade.",
	"← SSL 3.0 is the Windows XP of protocols. Beloved, ancient, full of holes.",
	"← supporting this in production is like driving without a seatbelt. On the highway. Blindfolded.",
	"← there are actual CVEs older than your junior developers targeting this protocol.",
	"← RFC 7568 formally declared this dead in 2015. A DECADE ago.",
	"← the 'S' in SSL 3.0 stands for 'Stop using this.'",
}

var tls12Sayings = []string{
	"← the workhorse. Solid, if you've got the right ciphers backing it up.",
	"← the Honda Civic of TLS. Not flashy, but it gets the job done.",
	"← perfectly fine, provided you're not pairing it with garbage ciphers.",
	"← the minimum acceptable version in the current decade.",
	"← 1.3 is right there, but sure, 1.2 works.",
	"← your compliance team can breathe. For now.",
	"← acceptable. Like showing up to a party on time instead of early.",
	"← still pulling its weight after all these years.",
	"← TLS 1.2: technically modern. Emotionally mid.",
	"← cipher suite selection matters more here than in 1.3. Choose wisely.",
	"← the 'I voted' sticker of TLS versions. You did the bare minimum.",
	"← solid choice. Not exciting, but your CISO won't yell at you.",
}

var tls13Sayings = []string{
	"← the gold standard. Someone here reads RFCs.",
	"← faster handshake, mandatory forward secrecy. Chef's kiss.",
	"← this is the way. No notes.",
	"← 0-RTT, AEAD-only ciphers, no legacy baggage. Beautiful.",
	"← the only version where you can't accidentally pick a bad cipher.",
	"← finally, a protocol designed by people who learned from 20 years of mistakes.",
	"← TLS 1.3: where the cipher suite list is short because everything in it is good.",
	"← approved by your security team, your compliance auditor, and your therapist.",
	"← forward secrecy isn't optional here. That's not a bug, it's the point.",
	"← if TLS versions were credit scores, this would be 850.",
	"← RFC 8446 done right. Respect.",
	"← the protocol equivalent of showing up in a tailored suit.",
}

var ssl30NotSupportedSayings = []string{
	"← good. This should never see the light of day.",
	"← correct. POODLE took care of this one.",
	"← as it should be. SSL 3.0 belongs in a history textbook.",
	"← one less nightmare to worry about.",
}

var tls10NotSupportedSayings = []string{
	"← good. One less compliance finding to deal with.",
	"← smart. Nothing of value was lost.",
	"← correct. Let the dead protocols rest.",
	"← whoever disabled this deserves a raise.",
}

var tls11NotSupportedSayings = []string{
	"← good. Nobody was using it anyway.",
	"← correct. Even TLS 1.1 wouldn't miss itself.",
	"← as expected. The forgotten middle child stays forgotten.",
	"← disabled and unbothered. As it should be.",
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

var ctPrivateCASayings = []string{
	"CT logs only track publicly-trusted CAs. Your internal CA isn't in the club.",
	"Private CAs don't submit to CT logs. This is expected, not suspicious.",
	"No public CT logs for internal certs — that's by design, not a problem.",
	"CT is for public trust. Your enterprise CA has its own trust model.",
	"Internal CAs live outside the public CT ecosystem. Nothing to see here.",
	"Public CT logs wouldn't know what to do with this cert even if you submitted it.",
	"Your internal PKI, your rules. CT logs are a public trust mechanism.",
	"This cert chains to a private root. CT logging doesn't apply here.",
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
		sass := tlsVersionSass(v.Version, v.Supported)
		if !v.Supported {
			if sass != "" {
				lines = append(lines, fmt.Sprintf("  %-10s %s  %s", v.Version, Theme.MutedStyle.Render("not supported"), Theme.MutedStyle.Render(sass)))
			} else {
				lines = append(lines, fmt.Sprintf("  %-10s %s", v.Version, Theme.MutedStyle.Render("not supported")))
			}
			continue
		}
		icon := StatusIcon(v.Grade)
		if sass != "" {
			sassStyle := Theme.MutedStyle
			if v.Grade == analyzer.WrittenInCrayon {
				sassStyle = Theme.ErrorStyle
			}
			lines = append(lines, fmt.Sprintf("  %-10s %s  %s", v.Version, icon, sassStyle.Render(sass)))
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

// truncateURI shortens a URI for display, keeping the beginning and end.
func truncateURI(uri string, maxLen int) string {
	if len(uri) <= maxLen {
		return uri
	}
	half := (maxLen - 3) / 2
	return uri[:half] + "..." + uri[len(uri)-half:]
}
