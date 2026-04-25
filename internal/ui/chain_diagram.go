package ui

import (
	"fmt"
	"math/rand"
	"strings"

	"github.com/thexsa/peep/internal/analyzer"
)

// RenderChainDiagram produces a visual chain-of-trust tree.
// Order: Leaf → Intermediate(s) → Root (as the user reads top to bottom).
func RenderChainDiagram(chain analyzer.ChainAnalysis) string {
	if len(chain.Certificates) == 0 {
		return Theme.ErrorStyle.Render("No certificates found in chain!")
	}

	header := Theme.BoldStyle.Render("CHAIN OF TRUST")
	var lines []string
	lines = append(lines, header)
	lines = append(lines, "")

	// Render in natural order: leaf first, root last
	for i, cert := range chain.Certificates {
		isLast := i == len(chain.Certificates)-1
		lines = append(lines, renderChainNode(cert, i, isLast, len(chain.Certificates))...)
	}

	// Chain-level notes
	if chain.HasMissingIntermediate {
		lines = append(lines, "")
		lines = append(lines, Theme.ErrorStyle.Render("[FAIL] Missing intermediate certificate(s)"))
		lines = append(lines, Theme.MutedStyle.Render("       You forgot the cert that vouches for the leaf. How is this in production?"))
	}

	if !chain.ChainOrderCorrect {
		lines = append(lines, "")
		lines = append(lines, Theme.ErrorStyle.Render("[FAIL] Chain order is wrong"))
		lines = append(lines, Theme.MutedStyle.Render("       The certs are shuffled. It's like reading a book from chapter 5 to chapter 1."))
	}

	if chain.HasUnnecessaryRoot {
		lines = append(lines, "")
		lines = append(lines, Theme.WarningStyle.Render("[WARN] Server is sending the Root CA cert — unnecessary"))
		lines = append(lines, Theme.MutedStyle.Render("       The root is already in the trust store. You're just wasting bandwidth."))
	}

	if chain.LeafOnlyMissingIntermediate {
		lines = append(lines, "")
		lines = append(lines, Theme.ErrorStyle.Render("[FAIL] Leaf-only chain — intermediate CA not included"))
		lines = append(lines, Theme.MutedStyle.Render("       The server sent ONLY the leaf cert. The issuing CA is NOT a root,"))
		lines = append(lines, Theme.MutedStyle.Render("       which means clients need BOTH the intermediate AND root trusted."))
		lines = append(lines, Theme.MutedStyle.Render("       That's not how this works. Include the intermediate in your chain."))
	}

	// Trust store verification
	if chain.TrustStoreVerified {
		lines = append(lines, "")
		lines = append(lines, Theme.SuccessStyle.Render("[PASS] Chain verified against system trust store"))
		lines = append(lines, Theme.MutedStyle.Render(fmt.Sprintf("       %s", chainVerifiedSaying())))
	} else if chain.VerificationError != "" {
		lines = append(lines, "")
		lines = append(lines, Theme.ErrorStyle.Render("[FAIL] Trust store verification failed"))
		lines = append(lines, Theme.MutedStyle.Render(fmt.Sprintf("       %s", chain.VerificationError)))
		lines = append(lines, Theme.MutedStyle.Render(fmt.Sprintf("       %s", chainFailedSaying())))
	}

	return ApplyBorder(lines, SectionBorder) + "\n"
}

// renderChainNode renders a single node in the chain tree.
func renderChainNode(cert analyzer.CertAnalysis, index int, isLast bool, total int) []string {
	var lines []string

	// Determine indent
	indent := strings.Repeat("  ", index)
	connector := indent + "|- "
	prefix := indent + "|  "
	if isLast {
		connector = indent + "`- "
		prefix = indent + "   "
	}
	if index == 0 {
		connector = ""
		prefix = "  "
	}

	name := cert.CommonName
	if name == "" {
		name = cert.Subject
	}

	// Role + name line
	roleLine := fmt.Sprintf("%s%s %s %s",
		connector,
		StatusIcon(cert.OverallGrade),
		Theme.BoldStyle.Render(cert.Role.String()),
		name,
	)
	lines = append(lines, roleLine)

	// Key details
	expiryStr := formatChainExpiry(cert)
	lines = append(lines, fmt.Sprintf("%sExpires: %s", prefix, expiryStr))

	// SANs for leaf
	if cert.Role == analyzer.RoleLeaf && len(cert.DNSNames) > 0 {
		sans := strings.Join(cert.DNSNames, ", ")
		lines = append(lines, fmt.Sprintf("%sCovers: %s", prefix, Theme.MutedStyle.Render(sans)))
	}

	lines = append(lines, fmt.Sprintf("%sKey: %s", prefix, Theme.MutedStyle.Render(cert.KeyType)))
	lines = append(lines, fmt.Sprintf("%sSerial: %s", prefix, Theme.MutedStyle.Render(cert.SerialNumber)))

	// Shortened fingerprint for chain view
	fp := cert.Fingerprint
	if len(fp) > 40 {
		fp = formatFingerprint(fp)
	}
	lines = append(lines, fmt.Sprintf("%sSHA-256: %s", prefix, Theme.MutedStyle.Render(fp)))

	// Self-signed / hostname mismatch
	if cert.IsSelfSigned && cert.Role == analyzer.RoleLeaf {
		lines = append(lines, fmt.Sprintf("%s%s", prefix, Theme.WarningStyle.Render("Self-signed!")))
	}
	if cert.Role == analyzer.RoleLeaf && !cert.HostnameMatch {
		lines = append(lines, fmt.Sprintf("%s%s", prefix, Theme.ErrorStyle.Render("Hostname does NOT match!")))
	}

	lines = append(lines, "")
	return lines
}

func formatChainExpiry(cert analyzer.CertAnalysis) string {
	if cert.IsExpired {
		return Theme.ErrorStyle.Render(fmt.Sprintf("EXPIRED %d days ago", -cert.DaysRemaining))
	}
	expiryDate := cert.NotAfter.Format("Jan 02, 2006")
	if cert.DaysRemaining > 90 {
		return Theme.SuccessStyle.Render(fmt.Sprintf("%d days (%s)", cert.DaysRemaining, expiryDate))
	}
	if cert.DaysRemaining > 30 {
		return Theme.WarningStyle.Render(fmt.Sprintf("%d days (%s)", cert.DaysRemaining, expiryDate))
	}
	return Theme.ErrorStyle.Render(fmt.Sprintf("%d days (%s)", cert.DaysRemaining, expiryDate))
}

var chainVerifiedSayings = []string{
	"The trust store gave this a thumbs up. You may proceed with your life.",
	"Verified. The OS trusts this chain. That's more than I can say for most things.",
	"System trust store says this checks out. For once, something works.",
	"All good. The chain is trusted. Now go worry about something else.",
	"Clean chain. The kind of result that makes you wonder what ELSE is broken.",
	"Trust store verification passed. Somebody actually configured this correctly.",
	"The chain is solid. Your OS agrees. Browsers agree. I reluctantly agree.",
	"Verified against the system trust store. No drama here.",
	"The chain checks out. If everything else worked this well, I'd be unemployed.",
	"Trusted. The PKI gods smile upon this chain.",
}

var chainFailedSayings = []string{
	"The trust store wants nothing to do with this chain. Can you blame it?",
	"Verification failed. Your users are seeing a big scary warning right now.",
	"The system trust store rejected this. Hard no. Fix the chain.",
	"Failed. The OS looked at this chain and said 'absolutely not.'",
	"Trust store says no. Browsers say no. I say no. Everybody says no.",
	"This chain couldn't pass verification at a lemonade stand.",
	"Untrusted. Your users are seeing a full-page error. You're welcome for the heads up.",
	"The chain is broken. Not 'kinda broken' — actually, completely broken.",
}

func chainVerifiedSaying() string {
	return chainVerifiedSayings[rand.Intn(len(chainVerifiedSayings))]
}

func chainFailedSaying() string {
	return chainFailedSayings[rand.Intn(len(chainFailedSayings))]
}
