package ui

import (
	"fmt"

	"github.com/thexsa/peep/internal/analyzer"
)

// RenderHandshakeCard renders the TLS handshake summary.
func RenderHandshakeCard(hs analyzer.HandshakeAnalysis) string {
	header := Theme.BoldStyle.Render("TLS HANDSHAKE")

	var lines []string
	lines = append(lines, header)
	lines = append(lines, "")

	// TLS Version
	versionGrade := StatusIcon(hs.VersionGrade)
	lines = append(lines, renderKV("TLS Version", fmt.Sprintf("%s  %s", hs.TLSVersion, versionGrade)))
	comment := tlsVersionComment(hs.TLSVersion)
	if comment != "" {
		lines = append(lines, fmt.Sprintf("                   %s", Theme.MutedStyle.Render(comment)))
	}

	// Cipher Suite
	cipherGrade := StatusIcon(hs.CipherGrade)
	lines = append(lines, renderKV("Cipher Suite", fmt.Sprintf("%s  %s", hs.CipherSuite, cipherGrade)))

	return ApplyBorder(lines, SectionBorder) + "\n"
}

func tlsVersionComment(version string) string {
	switch version {
	case "TLSv1.3":
		pool := []string{
			"Finally, someone who keeps up with the times.",
			"The gold standard. This is the way.",
			"TLS 1.3 — fast, secure, and not from the stone age.",
			"0-RTT handshakes and mandatory forward secrecy. We love to see it.",
			"Can't pick a bad cipher in 1.3. That's a feature, not a limitation.",
			"This is what happens when cryptographers get to design the protocol.",
			"Your browser is happy. Your security team is happy. Everyone's happy.",
			"TLS 1.3 — the protocol that proves you can have speed AND security.",
			"Fewer round trips, better security. It's almost like progress is possible.",
			"The only version where 'default settings' actually means 'good settings.'",
		}
		return PickSass(pool)
	case "TLSv1.2":
		pool := []string{
			"Fine. Not exciting, but it'll do. Like plain oatmeal.",
			"Acceptable. Provided the cipher suite isn't garbage.",
			"TLS 1.2 — the Honda Civic of encryption. Reliable, boring.",
			"Still the most deployed version on the internet. Inertia is powerful.",
			"Works fine if you pick good ciphers. Big 'if' for some people.",
			"1.3 exists, but 1.2 is paying the bills. Respect your elders.",
			"The 'good enough' of TLS. Which is honestly fine.",
			"Your auditor won't flag this. Your pen tester might raise an eyebrow.",
			"Solid, assuming the cipher suite list isn't a horror show.",
			"The version that works until someone picks RC4. Don't pick RC4.",
		}
		return PickSass(pool)
	case "TLSv1.1":
		pool := []string{
			"TLS 1.1?! What year is it? This was deprecated before TikTok existed.",
			"Deprecated since 2021. You're two protocol generations behind.",
			"TLS 1.1 — the Internet's equivalent of using a flip phone in 2026.",
			"Every major browser removed 1.1 support. Your server didn't get the memo.",
			"The only thing 1.1 fixed was BEAST, and then it got deprecated anyway.",
			"RFC 8996 didn't mince words: TLS 1.1 is done. Move on.",
			"Your TLS version should not be old enough to have a driver's license.",
			"If TLS 1.1 were a browser, it would be Internet Explorer.",
			"Negotiating TLS 1.1 in production is a cry for help.",
			"This protocol version is a relic. Update your config.",
		}
		return PickSass(pool)
	case "TLSv1.0":
		pool := []string{
			"TLS 1.0. NINETEEN NINETY NINE called and wants its protocol back.",
			"Screen door on a bank vault. Anyone can walk through it.",
			"This protocol has more holes than Swiss cheese at a shooting range.",
			"BEAST attack? Lucky13? POODLE? All of them work here. Welcome.",
			"PCI DSS said no to TLS 1.0 in 2018. Your server said 'watch me.'",
			"Congratulations, you're running a protocol from the Clinton administration.",
			"If this were a car, it would fail every safety inspection since 2010.",
			"TLS 1.0 — for when you want encryption that doesn't actually encrypt well.",
			"This is the 'we'll upgrade eventually' that never happened.",
			"Your compliance officer is going to need a moment.",
		}
		return PickSass(pool)
	case "SSLv3":
		pool := []string{
			"SSL 3.0?! This is a museum piece. POODLE destroyed this in 2014.",
			"This hasn't been safe since your smartphone was a flip phone.",
			"SSL 3.0 in a handshake is an instant fail. Everywhere. Always.",
		}
		return PickSass(pool)
	default:
		return ""
	}
}
