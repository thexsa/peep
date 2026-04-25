package education

import (
	"fmt"

	"github.com/thexsa/peep/internal/analyzer"
)

// BuildWarnings examines a diagnostic report and generates contextual warnings.
func BuildWarnings(report *analyzer.DiagnosticReport) []analyzer.Warning {
	var warnings []analyzer.Warning

	// TLS Version warnings
	warnings = append(warnings, checkTLSVersion(report.Handshake)...)

	// Cipher suite warnings
	warnings = append(warnings, checkCipherSuite(report.Handshake)...)

	// Certificate warnings
	for _, cert := range report.Chain.Certificates {
		warnings = append(warnings, checkCert(cert)...)
	}

	// Chain warnings
	warnings = append(warnings, checkChain(report.Chain)...)

	return warnings
}

func checkTLSVersion(hs analyzer.HandshakeAnalysis) []analyzer.Warning {
	var w []analyzer.Warning
	switch hs.TLSVersion {
	case "TLSv1.0":
		w = append(w, analyzer.Warning{
			Code:     "TLS_V10",
			Severity: analyzer.Stormy,
			Title:    "Ancient TLS Version: TLS 1.0",
			Detail:   "TLS 1.0 was deprecated by RFC 8996 in March 2021.",
			WhyNormal: "TLS 1.0 is active. This is like using a screen door for a bank vault; " +
				"it's technically a door, but anyone can get through it.",
			WhyRude: "TLS 1.0. Are you running this from a Windows XP box? " +
				"This version has more holes than Swiss cheese at a shooting range.",
		})
	case "TLSv1.1":
		w = append(w, analyzer.Warning{
			Code:     "TLS_V11",
			Severity: analyzer.Stormy,
			Title:    "Deprecated TLS Version: TLS 1.1",
			Detail:   "TLS 1.1 was deprecated by RFC 8996 in March 2021.",
			WhyNormal: "TLS 1.1 is hanging on by a thread. It's the Internet's equivalent " +
				"of using a flip phone in 2025 — technically works, but why?",
			WhyRude: "TLS 1.1 — deprecated, unloved, and yet here it is. " +
				"This protocol has been dead longer than your gym membership. Upgrade already.",
		})
	}
	return w
}

func checkCipherSuite(hs analyzer.HandshakeAnalysis) []analyzer.Warning {
	var w []analyzer.Warning
	if hs.CipherGrade == analyzer.Stormy {
		w = append(w, analyzer.Warning{
			Code:     "CIPHER_INSECURE",
			Severity: analyzer.Stormy,
			Title:    "Insecure Cipher Suite: " + hs.CipherSuite,
			Detail:   "This cipher suite is classified as insecure by Go's crypto/tls library.",
			WhyNormal: "This cipher suite has known vulnerabilities. It's like a lock that can be " +
				"picked with a credit card — it looks secure but really isn't.",
			WhyRude: "This cipher suite is so broken that script kiddies can crack it between " +
				"YouTube videos. Whoever configured this should be banned from touching servers.",
		})
	}
	return w
}

func checkCert(cert analyzer.CertAnalysis) []analyzer.Warning {
	var w []analyzer.Warning

	// Expired
	if cert.IsExpired {
		w = append(w, analyzer.Warning{
			Code:     "CERT_EXPIRED",
			Severity: analyzer.Stormy,
			Title:    certPrefix(cert) + "Certificate EXPIRED",
			Detail:   "This certificate expired " + pluralDays(-cert.DaysRemaining) + " ago.",
			WhyNormal: "This certificate has expired. It's like showing up to the airport with " +
				"a passport from 2019 — nobody's letting you through.",
			WhyRude: "The cert is EXPIRED. Dead. Gone. Pushing up digital daisies. " +
				"Every browser on Earth is screaming at your users right now. Fix. It.",
		})
	} else if cert.DaysRemaining <= 30 {
		w = append(w, analyzer.Warning{
			Code:     "CERT_EXPIRING_SOON",
			Severity: analyzer.Stormy,
			Title:    certPrefix(cert) + "Certificate Expiring VERY Soon",
			Detail:   "This certificate expires in " + pluralDays(cert.DaysRemaining) + ".",
			WhyNormal: "This cert is on life support. You have " + pluralDays(cert.DaysRemaining) +
				" before every visitor sees a big scary browser warning.",
			WhyRude: "You have " + pluralDays(cert.DaysRemaining) + " before this cert dies. " +
				"Stop reading this and go renew it. NOW. I'll wait.",
		})
	} else if cert.DaysRemaining <= 90 {
		w = append(w, analyzer.Warning{
			Code:     "CERT_EXPIRING",
			Severity: analyzer.Cloudy,
			Title:    certPrefix(cert) + "Certificate Expiring Soon",
			Detail:   "This certificate expires in " + pluralDays(cert.DaysRemaining) + ".",
			WhyNormal: "Not an emergency yet, but put it on the calendar. " +
				"Future-you will be grateful that present-you planned ahead.",
			WhyRude: "The cert expires in " + pluralDays(cert.DaysRemaining) + ". " +
				"Knowing how things work around here, nobody will renew it until the day after it breaks.",
		})
	}

	// Self-signed leaf
	if cert.IsSelfSigned && cert.Role == analyzer.RoleLeaf {
		w = append(w, analyzer.Warning{
			Code:     "CERT_SELF_SIGNED",
			Severity: analyzer.Cloudy,
			Title:    "Self-Signed Certificate",
			Detail:   "This certificate was signed by itself, not by a trusted CA.",
			WhyNormal: "This certificate signed itself. That's like writing 'I'm definitely not a robot' " +
				"on a piece of paper and expecting TSA to accept it.",
			WhyRude: "Self-signed cert. So the server basically said 'trust me bro' and you're supposed " +
				"to be okay with that? This wouldn't pass a security audit at a lemonade stand.",
		})
	}

	// Weak key
	if cert.KeyGrade == analyzer.Stormy {
		w = append(w, analyzer.Warning{
			Code:     "CERT_WEAK_KEY",
			Severity: analyzer.Stormy,
			Title:    certPrefix(cert) + "Weak Key",
			Detail:   "Key type: " + cert.KeyType + ".",
			WhyNormal: "This cert's key is shorter than a tweet. " +
				"A determined attacker could crack it during a lunch break.",
			WhyRude: "This key is so weak that my grandma could brute-force it " +
				"with a calculator from 1995. Get a real key.",
		})
	}

	// SHA-1 signature
	if cert.SignatureGrade == analyzer.Stormy {
		w = append(w, analyzer.Warning{
			Code:     "CERT_SHA1",
			Severity: analyzer.Stormy,
			Title:    certPrefix(cert) + "Insecure Signature Algorithm: " + cert.SignatureAlg,
			Detail:   "This certificate uses a signature algorithm with known weaknesses.",
			WhyNormal: "SHA-1 signatures have been broken since 2017. At this point, using it is " +
				"basically a tradition — a bad one, like putting pineapple on pizza.",
			WhyRude: "SHA-1?! Google literally created a collision attack for this in 2017. " +
				"Using this in production is professional negligence. Update. The. Cert.",
		})
	}

	// Hostname mismatch
	if cert.Role == analyzer.RoleLeaf && !cert.HostnameMatch {
		w = append(w, analyzer.Warning{
			Code:     "CERT_HOSTNAME_MISMATCH",
			Severity: analyzer.Stormy,
			Title:    "Hostname Mismatch",
			Detail:   "The certificate does not cover the hostname you connected to.",
			WhyNormal: "The cert was issued for a different hostname. It's like showing up to a hotel " +
				"with a reservation under someone else's name — they're not giving you the room.",
			WhyRude: "The cert doesn't match the hostname. Someone installed the WRONG CERT. " +
				"This is TLS 101, people. Read the Subject Alternative Names before installing.",
		})
	}

	return w
}

func checkChain(chain analyzer.ChainAnalysis) []analyzer.Warning {
	var w []analyzer.Warning

	if chain.HasMissingIntermediate {
		w = append(w, analyzer.Warning{
			Code:     "CHAIN_MISSING_INTERMEDIATE",
			Severity: analyzer.Stormy,
			Title:    "Missing Intermediate Certificate",
			Detail:   "The server did not send all required intermediate certificates.",
			WhyNormal: "The server forgot to send an intermediate cert. It's like mailing a letter " +
				"with no return address and wondering why nobody writes back.",
			WhyRude: "You forgot the intermediate cert. The ENTIRE chain of trust is broken. " +
				"Half the browsers on earth can't verify this cert. How did this pass testing? DID you test?",
		})
	}

	if !chain.ChainOrderCorrect {
		w = append(w, analyzer.Warning{
			Code:     "CHAIN_WRONG_ORDER",
			Severity: analyzer.Stormy,
			Title:    "Certificate Chain in Wrong Order",
			Detail:   "Certificates should be ordered: leaf → intermediate(s) → root.",
			WhyNormal: "The cert chain is shuffled like a deck of cards. " +
				"Some clients can figure it out, but many will just give up and show an error.",
			WhyRude: "The chain is in the wrong order. Did someone just throw the certs into the " +
				"config file and hope for the best? That's not how PKI works.",
		})
	}

	if chain.HasUnnecessaryRoot {
		w = append(w, analyzer.Warning{
			Code:     "CHAIN_UNNECESSARY_ROOT",
			Severity: analyzer.Cloudy,
			Title:    "Unnecessary Root CA in Chain",
			Detail:   "The server is sending the root CA certificate, which clients already have.",
			WhyNormal: "The root cert is already in every browser's trust store. " +
				"Sending it is like bringing your own chair to a restaurant — unnecessary and a bit weird.",
			WhyRude: "You're sending the root cert. Why? The client ALREADY HAS IT. " +
				"You're just wasting bandwidth to prove you don't understand how trust stores work.",
		})
	}

	if chain.VerificationError != "" {
		w = append(w, analyzer.Warning{
			Code:     "CHAIN_VERIFICATION_FAILED",
			Severity: analyzer.Stormy,
			Title:    "Chain Verification Failed",
			Detail:   "Trust store verification error: " + chain.VerificationError,
			WhyNormal: "The system's trust store couldn't verify this chain. " +
				"This means browsers will show a scary warning page instead of your site.",
			WhyRude: "Verification FAILED. The trust store looked at this chain and said 'nah.' " +
				"Your users are seeing a giant red warning page. Congrats.",
		})
	}

	return w
}

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
