package ui

import (
	"fmt"
	"math/rand"

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
	return pool[rand.Intn(len(pool))]
}

// RandomExpiryComment returns a random quip about cert expiry timing.
func RandomExpiryComment(daysLeft int) string {
	if daysLeft > 365 {
		return longExpirySayings[rand.Intn(len(longExpirySayings))]
	}
	if daysLeft > 30 {
		return mediumExpirySayings[rand.Intn(len(mediumExpirySayings))]
	}
	if daysLeft > 14 {
		return shortExpirySayings[rand.Intn(len(shortExpirySayings))]
	}
	return criticalExpirySayings[rand.Intn(len(criticalExpirySayings))]
}

// RandomExpiredComment returns a random quip about an expired cert.
func RandomExpiredComment() string {
	return expiredSayings[rand.Intn(len(expiredSayings))]
}

// RenderOverallStatus renders the overall scan status.
func RenderOverallStatus(status analyzer.HealthStatus) string {
	badge := StatusBadge(status)
	saying := RandomSaying(status)

	header := Theme.BoldStyle.Render("VERDICT")
	content := fmt.Sprintf("%s\n  %s\n  %s", header, badge, Theme.MutedStyle.Render(saying))
	return "\n" + Theme.SectionStyle.Render(content) + "\n"
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
