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
	noteW := ContentWidth(7) // 7 = "       " indent
	noteIndent := "       "

	// These conditions overlap (especially for single-cert chains).
	// Show only the most specific applicable finding.
	switch {
	case chain.HasWrongIntermediate:
		lines = append(lines, "")
		lines = append(lines, Theme.ErrorStyle.Render("[FAIL] Wrong Issuing CA in server response"))
		lines = append(lines, wrapBlock("The server sent an intermediate certificate with the correct issuer name, but the wrong key. The leaf cert was NOT signed by this intermediate. This usually happens after a CA renewal or re-key — the old leaf cert needs to be re-issued with the new CA key.", noteIndent, noteW, Theme.MutedStyle)...)
		lines = append(lines, wrapBlock(wrongIntermediateSaying(), noteIndent, noteW, Theme.MutedStyle)...)
	case chain.LeafOnlyMissingIntermediate:
		lines = append(lines, "")
		lines = append(lines, Theme.ErrorStyle.Render("[FAIL] Incomplete chain — server sent only the leaf certificate"))
		lines = append(lines, wrapBlock("The server sent ONLY the leaf cert and no issuing CA. The issuer is an intermediate CA (not a root), so clients cannot verify the chain without it. Include the intermediate in your cert bundle.", noteIndent, noteW, Theme.MutedStyle)...)
		lines = append(lines, wrapBlock(noIssuingCAChainSaying(), noteIndent, noteW, Theme.MutedStyle)...)
	case chain.HasMissingIntermediate:
		lines = append(lines, "")
		lines = append(lines, Theme.ErrorStyle.Render("[FAIL] Missing intermediate certificate(s)"))
		lines = append(lines, wrapBlock("The server did not send all required intermediate certificates. Clients cannot build a trust path to a root CA without them.", noteIndent, noteW, Theme.MutedStyle)...)
		lines = append(lines, wrapBlock(noIssuingCAChainSaying(), noteIndent, noteW, Theme.MutedStyle)...)
	case chain.NoIssuingCAInResponse:
		lines = append(lines, "")
		lines = append(lines, Theme.ErrorStyle.Render("[FAIL] No Issuing CA in server response"))
		lines = append(lines, wrapBlock("The server did not include the issuing CA certificate in its TLS handshake. Clients cannot build a trust path without it. This must be fixed.", noteIndent, noteW, Theme.MutedStyle)...)
		lines = append(lines, wrapBlock(noIssuingCAChainSaying(), noteIndent, noteW, Theme.MutedStyle)...)
	}

	if !chain.ChainOrderCorrect {
		lines = append(lines, "")
		lines = append(lines, Theme.ErrorStyle.Render("[FAIL] Chain order is wrong"))
		lines = append(lines, wrapBlock("The certs are shuffled. It's like reading a book from chapter 5 to chapter 1.", noteIndent, noteW, Theme.MutedStyle)...)
	}

	if chain.HasUnnecessaryRoot {
		lines = append(lines, "")
		lines = append(lines, Theme.WarningStyle.Render("[WARN] Server is sending the Root CA cert — unnecessary"))
		lines = append(lines, wrapBlock("The root is already in the trust store. You're just wasting bandwidth.", noteIndent, noteW, Theme.MutedStyle)...)
	}

	// Trust store verification
	if chain.TrustStoreVerified {
		lines = append(lines, "")
		lines = append(lines, Theme.SuccessStyle.Render("[PASS] Chain verified against system trust store"))
		lines = append(lines, wrapBlock(chainVerifiedSaying(), noteIndent, noteW, Theme.MutedStyle)...)
	} else if chain.VerificationError != "" {
		lines = append(lines, "")
		lines = append(lines, Theme.ErrorStyle.Render("[FAIL] Trust store verification failed"))
		lines = append(lines, wrapBlock(chain.VerificationError, noteIndent, noteW, Theme.MutedStyle)...)
		lines = append(lines, wrapBlock(chainFailedSaying(), noteIndent, noteW, Theme.MutedStyle)...)
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
		sanPrefix := prefix + "Covers: "
		// Build a continuation indent that matches the prefix length
		contIndent := prefix + "        " // same width as "Covers: "
		sanW := ContentWidth(len(sanPrefix))
		wrappedSans := WrapText(sans, contIndent, sanW)
		for i, sl := range wrappedSans {
			if i == 0 {
				lines = append(lines, sanPrefix+Theme.MutedStyle.Render(sl))
			} else {
				lines = append(lines, contIndent+Theme.MutedStyle.Render(sl))
			}
		}
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

var noIssuingCAChainSayings = []string{
	"The server said 'here's the leaf, figure out the rest.' Spoiler: clients can't.",
	"No intermediate. No chain. No trust. No bueno.",
	"The issuing CA is AWOL. Someone forgot to include it in the cert bundle.",
	"It's like handing someone a letter with no signature and expecting them to trust it.",
	"The server sent one cert and called it a day. That's not how PKI works.",
	"Missing the issuing CA is like a resume with no references — nobody's calling you back.",
	"The chain has exactly one link. That's not a chain. That's a pendant.",
	"The trust chain starts and ends with the leaf. That's a trust dot, not a chain.",
	"Whoever bundled this cert forgot the most important part. The part that makes it work.",
	"One cert to rule them all? No. One cert to confuse them all.",
}

func noIssuingCAChainSaying() string {
	return noIssuingCAChainSayings[rand.Intn(len(noIssuingCAChainSayings))]
}

func chainVerifiedSaying() string {
	return chainVerifiedSayings[rand.Intn(len(chainVerifiedSayings))]
}

func chainFailedSaying() string {
	return chainFailedSayings[rand.Intn(len(chainFailedSayings))]
}

var wrongIntermediateSayings = []string{
	"The name's right. The key's wrong. It's like showing up with someone else's badge and expecting to get in.",
	"The CA was renewed but the leaf cert wasn't re-issued. Close, but no cigar.",
	"Right name, wrong key. That's identity theft in PKI terms.",
	"The intermediate has the correct label on a completely different bottle. Re-issue the leaf.",
	"Someone renewed the CA and forgot to re-sign everything underneath it. Classic.",
	"This is the PKI equivalent of changing the locks but not giving anyone new keys.",
	"The issuer name matches, but the math doesn't. Cryptography doesn't do 'close enough.'",
	"The CA got a new key pair and nobody told the leaf cert. Awkward.",
	"New CA key, old leaf signature. That's a broken chain with extra steps.",
	"The signature verification failed because this intermediate is the new version. The leaf was signed by the old one.",
}

func wrongIntermediateSaying() string {
	return wrongIntermediateSayings[rand.Intn(len(wrongIntermediateSayings))]
}
