package ui

import (
	"fmt"
	"strings"

	"github.com/thexsa/peep/internal/analyzer"
)

// StatusBadge returns a styled status label.
func StatusBadge(status analyzer.HealthStatus) string {
	switch status {
	case analyzer.MainCharacterEnergy:
		return Theme.SuccessStyle.Render("Main Character Energy")
	case analyzer.MallCopCredentials:
		return Theme.WarningStyle.Render("Mall Cop Credentials")
	case analyzer.WrittenInCrayon:
		return Theme.ErrorStyle.Render("Appears to be Written in Crayon")
	default:
		return Theme.MutedStyle.Render("Unknown")
	}
}

// StatusIcon returns just the icon for a status.
func StatusIcon(status analyzer.HealthStatus) string {
	switch status {
	case analyzer.MainCharacterEnergy:
		return Theme.SuccessStyle.Render("[PASS]")
	case analyzer.MallCopCredentials:
		return Theme.WarningStyle.Render("[WARN]")
	case analyzer.WrittenInCrayon:
		return Theme.ErrorStyle.Render("[FAIL]")
	default:
		return "[????]"
	}
}

// RandomSaying returns a random quip for the given status.
func RandomSaying(status analyzer.HealthStatus) string {
	var pool []string
	switch status {
	case analyzer.MainCharacterEnergy:
		pool = mainCharacterSayings
	case analyzer.MallCopCredentials:
		pool = mallCopSayings
	case analyzer.WrittenInCrayon:
		pool = crayonSayings
	default:
		return ""
	}
	return PickSass(pool)
}

// RandomExpiryComment returns a random quip about cert expiry timing.
func RandomExpiryComment(daysLeft int) string {
	if daysLeft > 365 {
		return PickSass(longExpirySayings)
	}
	if daysLeft > 30 {
		return PickSass(mediumExpirySayings)
	}
	if daysLeft > 14 {
		return PickSass(shortExpirySayings)
	}
	return PickSass(criticalExpirySayings)
}

// RandomExpiredComment returns a random quip about an expired cert.
func RandomExpiredComment() string {
	return PickSass(expiredSayings)
}

// RenderOverallStatus renders the overall scan status (legacy single-verdict).
// Use RenderDualVerdict for the new dual-scale output.
func RenderOverallStatus(status analyzer.HealthStatus) string {
	return RenderDualVerdict(analyzer.DualVerdict{
		BrowserVerdict: status,
		ServiceVerdict: status,
	})
}

// RenderDualVerdict renders the dual-scale verdict block.
// When both verdicts match, it shows a clean single verdict.
// When they differ, it shows both with root cause codes and a sarcastic quip.
// Special case: when the ONLY issue is CHAIN_UNNECESSARY_ROOT, it shows
// "Unnecessary Main Character Arc" — a unique verdict for this specific scenario.
func RenderDualVerdict(v analyzer.DualVerdict) string {
	var lines []string

	header := Theme.BoldStyle.Render("VERDICTS")
	lines = append(lines, header)
	lines = append(lines, "")

	// Special case: the ONLY issue is the unnecessary root cert
	if isUnnecessaryRootOnly(v) {
		badge := Theme.WarningStyle.Render("⚡ Unnecessary Main Character Arc")
		lines = append(lines, fmt.Sprintf("  %s", badge))
		lines = append(lines, fmt.Sprintf("  %s", Theme.MutedStyle.Render(PickSass(unnecessaryRootSayings))))
	} else if v.BrowserVerdict == v.ServiceVerdict {
		// Same verdict — clean single line
		lines = append(lines, fmt.Sprintf("  %s", StatusBadge(v.ServiceVerdict)))
		lines = append(lines, fmt.Sprintf("  %s", Theme.MutedStyle.Render(RandomSaying(v.ServiceVerdict))))
	} else {
		// Different verdicts — show both
		lines = append(lines, fmt.Sprintf("  🌐 Browser:      %s", StatusBadge(v.BrowserVerdict)))
		lines = append(lines, fmt.Sprintf("  🤖 Service/API:  %s", StatusBadge(v.ServiceVerdict)))

		// Root cause codes
		if len(v.RootCauses) > 0 {
			lines = append(lines, "")
			for _, code := range v.RootCauses {
				lines = append(lines, fmt.Sprintf("     👉 %s", Theme.MutedStyle.Render(code)))
			}
		}

		// Sarcastic quip about the divergence
		lines = append(lines, "")
		if v.BrowserVerdict == analyzer.MainCharacterEnergy && v.ServiceVerdict == analyzer.MallCopCredentials {
			lines = append(lines, fmt.Sprintf("  %s", Theme.MutedStyle.Render(PickSass(browserPassServiceWarnSayings))))
		} else if v.BrowserVerdict == analyzer.MainCharacterEnergy && v.ServiceVerdict == analyzer.WrittenInCrayon {
			lines = append(lines, fmt.Sprintf("  %s", Theme.MutedStyle.Render(PickSass(browserPassServiceFailSayings))))
		} else if v.BrowserVerdict == analyzer.MallCopCredentials && v.ServiceVerdict == analyzer.WrittenInCrayon {
			lines = append(lines, fmt.Sprintf("  %s", Theme.MutedStyle.Render(PickSass(browserWarnServiceFailSayings))))
		}
	}

	return "\n" + Theme.SectionStyle.Render(fmt.Sprintf("%s", strings.Join(lines, "\n"))) + "\n"
}

// isUnnecessaryRootOnly returns true when the ONLY divergence between browser
// and service verdicts is CHAIN_UNNECESSARY_ROOT — the server sent the root CA
// cert in the chain (harmless but wasteful).
func isUnnecessaryRootOnly(v analyzer.DualVerdict) bool {
	return v.BrowserVerdict == analyzer.MainCharacterEnergy &&
		v.ServiceVerdict == analyzer.MallCopCredentials &&
		len(v.RootCauses) == 1 &&
		v.RootCauses[0] == "CHAIN_UNNECESSARY_ROOT"
}

// --- Saying pools (10-20 each) ---

var mainCharacterSayings = []string{
	"Congrats, you didn't screw this one up. Everything's fine.",
	"This cert woke up and chose excellence.",
	"Chef's kiss. No notes.",
	"If all certs were like this, I'd be out of a job.",
	"Somebody here actually reads documentation. Respect.",
	"This is what happens when competent people touch servers.",
	"Gold star. Put it on the fridge.",
	"The rare cert that doesn't make me question humanity.",
	"This setup is tighter than my jeans after Thanksgiving.",
	"Nothing to roast here. How disappointing.",
	"Someone's getting a raise. Or at least they should be.",
	"This is so clean I'm suspicious. You sure this is production?",
	"TLS config so good it brought a tear to my eye.",
	"Finally, a cert that doesn't need therapy.",
	"Flawless. Like a perfectly parallel-parked car.",
}

var mallCopSayings = []string{
	"It works, but barely. Like your New Year's resolutions.",
	"Not broken, but I wouldn't brag about it either.",
	"This has 'we'll fix it later' energy written all over it.",
	"Technically functional. The participation trophy of TLS.",
	"It'll hold. Like duct tape on a bumper.",
	"This cert is the 'C minus' of the class — passing, but just barely.",
	"Sure, it works. So does a screen door on a submarine. Briefly.",
	"You could do worse. You could also do a LOT better.",
	"This is giving 'I'll deal with it Monday' vibes.",
	"Functional but sad. Like airport food.",
	"It's not a fire. It's more of a... smolder.",
	"This setup has 'intern did it' written all over it.",
	"The cert equivalent of wearing socks with sandals.",
	"It technically passes. Like a student who copies just enough.",
	"Middle of the road. Which is exactly where you get hit by traffic.",
}

var crayonSayings = []string{
	"This is a dumpster fire. Whoever set this up should update their resume.",
	"Every browser on Earth is screaming at your users right now.",
	"This cert is so broken it belongs in a museum.",
	"I've seen better security on a diary with a plastic lock.",
	"This wouldn't pass a security audit at a lemonade stand.",
	"Whoever configured this should be banned from touching servers.",
	"This is the TLS equivalent of leaving your front door wide open. In a hurricane.",
	"If this cert were a building, it would've been condemned.",
	"I'm not mad, I'm disappointed. Actually no, I'm mad too.",
	"This is professional negligence with extra steps.",
	"Did someone configure this by randomly smashing the keyboard?",
	"The fact that this is in production keeps me up at night.",
	"Congratulations, you've achieved a new low.",
	"This setup is held together by thoughts and prayers.",
	"I wouldn't trust this cert to guard a parking meter.",
	"Someone typed 'yolo' into the server config and walked away.",
}

var expiredSayings = []string{
	"Dead. Gone. Pushing up digital daisies.",
	"This cert has been expired longer than your gym membership.",
	"Expired. Every browser is showing the big scary warning page. Congrats.",
	"This cert died and nobody noticed. Says a lot.",
	"Expired. Like showing up to the airport with a passport from 2019.",
	"RIP to this cert. Nobody sent flowers.",
	"This cert is so expired the expiry date has an expiry date.",
	"Deceased. The cert has left the building.",
	"Expired. You know who else noticed? All your users.",
	"This cert's been dead so long it qualifies for archaeological study.",
}

var longExpirySayings = []string{
	"You'll probably change jobs before this expires.",
	"At least SOMETHING here was done right.",
	"This one's got legs. Good for you.",
	"Set it and forget it. But maybe don't actually forget it.",
	"Future you's problem. Present you can relax.",
}

var mediumExpirySayings = []string{
	"Plenty of time. Don't get too comfortable though.",
	"Looking fine for now. Put a reminder on the calendar.",
	"Still got runway. Don't waste it.",
	"Healthy, but not immortal. Keep an eye on it.",
}

var shortExpirySayings = []string{
	"Tick tock, procrastinator.",
	"The clock is ticking. You hear it, right?",
	"Getting real close to 'your problem' territory.",
	"Time to start planning that renewal. Like, now.",
	"This is the part where smart people start renewing.",
	"Renewal time. Unless you enjoy 3am outage calls.",
}

var criticalExpirySayings = []string{
	"This is YOUR fault when it expires.",
	"Stop reading this and go renew it. NOW. I'll wait.",
	"You're playing chicken with an expiry date. Spoiler: you lose.",
	"Days, not weeks. DAYS. Move it.",
	"If this expires on your watch, that's a resume event.",
	"This cert is on life support. Pull the renewal trigger.",
}

// RandomScanComment returns a sarcastic remark about the scan duration.
func RandomScanComment() string {
	return PickSass(scanDurationSayings)
}

var scanDurationSayings = []string{
	"That's faster than your last DNS lookup.",
	"Faster than reading the man page for openssl s_client.",
	"You're welcome. That would've taken 20 minutes with openssl.",
	"And that's without the existential dread of reading ASN.1.",
	"Quicker than a standup meeting, and actually useful.",
	"That's less time than it takes to google 'how to check TLS cert.'",
	"Done before your coffee got cold. You're welcome.",
	"Faster than filing a Jira ticket about it.",
	"We just did what 3 engineers and a wiki page couldn't.",
	"That's the entire chain, verified, explained, and judged. In milliseconds.",
}

// --- Dual-verdict divergence saying pools ---

var browserPassServiceWarnSayings = []string{
	"Browsers will connect just fine. Your Go microservice? Not so much.",
	"Chrome doesn't care. Your API gateway does. Fix the warnings.",
	"Users won't notice. Your monitoring dashboard will.",
	"Browsers are forgiving. curl with strict TLS? Less so.",
	"Works in every browser. Fails the code review for your service mesh.",
	"Your users are fine. Your SRE team has questions.",
	"Modern browsers auto-heal this. Java HttpsURLConnection? Throws an exception.",
	"Browser compatibility: A+. API reliability: C-. Pick your audience.",
	"Chrome rebuilt your broken chain for you. OpenSSL won't be so kind.",
	"Browsers have seen worse. Programmatic clients have standards.",
}

var browserPassServiceFailSayings = []string{
	"Browsers will connect. Every API client will reject this outright.",
	"Chrome can handle this mess. Go's crypto/tls will hard-fail.",
	"Your website works. Your API is a dumpster fire. Priorities.",
	"Users browse fine. Services fail hard. The duality of bad TLS.",
	"Technically browsable. Programmatically catastrophic.",
	"Browsers forgive a lot. Production services forgive nothing.",
	"Your users won't notice. Your backend integrations already have.",
	"Chrome will auto-fix this. Java will throw SSLHandshakeException and ruin your day.",
	"Browser: 'I got you, fam.' OpenSSL: 'Certificate verify failed. Goodbye.'",
	"The website works. The API returns 'unable to verify the first certificate.' Fun.",
}

var browserWarnServiceFailSayings = []string{
	"Browsers are struggling. API clients have given up entirely.",
	"Even browsers are raising eyebrows. Services won't even try.",
	"Browsers show a warning. Services throw an exception. Neither is great.",
	"Your browser users get a scary page. Your API clients get a stack trace.",
	"Browsers are barely holding on. Programmatic clients already left.",
	"Warning in Chrome, hard fail in production. That's a rough combo.",
	"The browser is being polite about it. The API client is not.",
	"Browsers: 'Proceed anyway?' APIs: 'No. Absolutely not.'",
}
