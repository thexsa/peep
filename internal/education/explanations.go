package education

import (
	"fmt"
	"math/rand"

	"github.com/thexsa/peep/internal/analyzer"
)

// BuildWarnings examines a diagnostic report and generates contextual warnings.
func BuildWarnings(report *analyzer.DiagnosticReport) []analyzer.Warning {
	var warnings []analyzer.Warning

	warnings = append(warnings, checkTLSVersion(report.Handshake)...)
	warnings = append(warnings, checkCipherSuite(report.Handshake)...)

	for _, cert := range report.Chain.Certificates {
		warnings = append(warnings, checkCert(cert)...)
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
		})
	case "TLSv1.1":
		w = append(w, analyzer.Warning{
			Code:     "TLS_V11",
			Severity: analyzer.WrittenInCrayon,
			Title:    "Deprecated TLS Version: TLS 1.1",
			Detail:   "TLS 1.1 was deprecated by RFC 8996 in March 2021.",
			Why:      pick(tlsOldSayings),
		})
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
		})
	} else if cert.DaysRemaining <= 14 {
		w = append(w, analyzer.Warning{
			Code:     "CERT_EXPIRING_SOON",
			Severity: analyzer.WrittenInCrayon,
			Title:    certPrefix(cert) + "Certificate Expiring VERY Soon",
			Detail:   "This certificate expires in " + pluralDays(cert.DaysRemaining) + ".",
			Why:      pick(certExpiringSoonSayings),
		})
	} else if cert.DaysRemaining <= 30 {
		w = append(w, analyzer.Warning{
			Code:     "CERT_EXPIRING",
			Severity: analyzer.MallCopCredentials,
			Title:    certPrefix(cert) + "Certificate Expiring Soon",
			Detail:   "This certificate expires in " + pluralDays(cert.DaysRemaining) + ".",
			Why:      pick(certExpiringSayings),
		})
	}

	if cert.IsSelfSigned && cert.Role == analyzer.RoleLeaf {
		w = append(w, analyzer.Warning{
			Code:     "CERT_SELF_SIGNED",
			Severity: analyzer.MallCopCredentials,
			Title:    "Self-Signed Certificate",
			Detail:   "This certificate was signed by itself, not by a trusted CA.",
			Why:      pick(selfSignedSayings),
		})
	}

	if cert.KeyGrade == analyzer.WrittenInCrayon {
		w = append(w, analyzer.Warning{
			Code:     "CERT_WEAK_KEY",
			Severity: analyzer.WrittenInCrayon,
			Title:    certPrefix(cert) + "Weak Key",
			Detail:   "Key type: " + cert.KeyType + ".",
			Why:      pick(weakKeySayings),
		})
	}

	if cert.SignatureGrade == analyzer.WrittenInCrayon {
		w = append(w, analyzer.Warning{
			Code:     "CERT_SHA1",
			Severity: analyzer.WrittenInCrayon,
			Title:    certPrefix(cert) + "Insecure Signature Algorithm: " + cert.SignatureAlg,
			Detail:   "This certificate uses a signature algorithm with known weaknesses.",
			Why:      pick(sha1Sayings),
		})
	}

	if cert.Role == analyzer.RoleLeaf && !cert.HostnameMatch {
		w = append(w, analyzer.Warning{
			Code:     "CERT_HOSTNAME_MISMATCH",
			Severity: analyzer.WrittenInCrayon,
			Title:    "Hostname Mismatch",
			Detail:   "The certificate does not cover the hostname you connected to.",
			Why:      pick(hostnameMismatchSayings),
		})
	}

	return w
}

func checkChain(chain analyzer.ChainAnalysis) []analyzer.Warning {
	var w []analyzer.Warning

	if chain.HasMissingIntermediate {
		w = append(w, analyzer.Warning{
			Code:     "CHAIN_MISSING_INTERMEDIATE",
			Severity: analyzer.WrittenInCrayon,
			Title:    "Missing Intermediate Certificate",
			Detail:   "The server did not send all required intermediate certificates.",
			Why:      pick(missingIntermediateSayings),
		})
	}

	if chain.LeafOnlyMissingIntermediate {
		w = append(w, analyzer.Warning{
			Code:     "CHAIN_LEAF_ONLY",
			Severity: analyzer.WrittenInCrayon,
			Title:    "Leaf-Only Chain — Intermediate CA Not Included",
			Detail:   "Only the leaf cert was sent. Its issuer is NOT a root CA.",
			Why:      pick(leafOnlySayings),
		})
	}

	if !chain.ChainOrderCorrect {
		w = append(w, analyzer.Warning{
			Code:     "CHAIN_WRONG_ORDER",
			Severity: analyzer.WrittenInCrayon,
			Title:    "Certificate Chain in Wrong Order",
			Detail:   "Certificates should be ordered: leaf → intermediate(s) → root.",
			Why:      pick(wrongOrderSayings),
		})
	}

	if chain.HasUnnecessaryRoot {
		w = append(w, analyzer.Warning{
			Code:     "CHAIN_UNNECESSARY_ROOT",
			Severity: analyzer.MallCopCredentials,
			Title:    "Unnecessary Root CA in Chain",
			Detail:   "The server is sending the root CA certificate, which clients already have.",
			Why:      pick(unnecessaryRootSayings),
		})
	}

	if chain.VerificationError != "" {
		w = append(w, analyzer.Warning{
			Code:     "CHAIN_VERIFICATION_FAILED",
			Severity: analyzer.WrittenInCrayon,
			Title:    "Chain Verification Failed",
			Detail:   "Trust store verification error: " + chain.VerificationError,
			Why:      pick(verificationFailedSayings),
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
