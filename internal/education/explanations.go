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
			Severity: analyzer.WrittenInCrayon,
			Title:    "Ancient TLS Version: TLS 1.0",
			Detail:   "TLS 1.0 was deprecated by RFC 8996 in March 2021.",
			Why: "TLS 1.0 has more holes than Swiss cheese at a shooting range. " +
				"This version was born in 1999 — it's old enough to rent a car. Upgrade.",
		})
	case "TLSv1.1":
		w = append(w, analyzer.Warning{
			Code:     "TLS_V11",
			Severity: analyzer.WrittenInCrayon,
			Title:    "Deprecated TLS Version: TLS 1.1",
			Detail:   "TLS 1.1 was deprecated by RFC 8996 in March 2021.",
			Why: "This protocol has been dead longer than your gym membership. " +
				"Deprecated since 2021, yet here it is. Upgrade already.",
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
			Why: "This cipher suite is so broken that script kiddies can crack it " +
				"between YouTube videos. Whoever configured this should be banned from touching servers.",
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
			Severity: analyzer.WrittenInCrayon,
			Title:    certPrefix(cert) + "Certificate EXPIRED",
			Detail:   "This certificate expired " + pluralDays(-cert.DaysRemaining) + " ago.",
			Why: "The cert is EXPIRED. Dead. Gone. Pushing up digital daisies. " +
				"Every browser on Earth is screaming at your users right now. Fix. It.",
		})
	} else if cert.DaysRemaining <= 30 {
		w = append(w, analyzer.Warning{
			Code:     "CERT_EXPIRING_SOON",
			Severity: analyzer.WrittenInCrayon,
			Title:    certPrefix(cert) + "Certificate Expiring VERY Soon",
			Detail:   "This certificate expires in " + pluralDays(cert.DaysRemaining) + ".",
			Why: "You have " + pluralDays(cert.DaysRemaining) + " before this cert dies. " +
				"Stop reading this and go renew it. NOW. I'll wait.",
		})
	} else if cert.DaysRemaining <= 90 {
		w = append(w, analyzer.Warning{
			Code:     "CERT_EXPIRING",
			Severity: analyzer.MallCopCredentials,
			Title:    certPrefix(cert) + "Certificate Expiring Soon",
			Detail:   "This certificate expires in " + pluralDays(cert.DaysRemaining) + ".",
			Why: "The cert expires in " + pluralDays(cert.DaysRemaining) + ". " +
				"Knowing how things work around here, nobody will renew it until the day after it breaks.",
		})
	}

	// Self-signed leaf
	if cert.IsSelfSigned && cert.Role == analyzer.RoleLeaf {
		w = append(w, analyzer.Warning{
			Code:     "CERT_SELF_SIGNED",
			Severity: analyzer.MallCopCredentials,
			Title:    "Self-Signed Certificate",
			Detail:   "This certificate was signed by itself, not by a trusted CA.",
			Why: "Self-signed cert. The server basically said 'trust me bro' and you're supposed " +
				"to be okay with that? This wouldn't pass a security audit at a lemonade stand.",
		})
	}

	// Weak key
	if cert.KeyGrade == analyzer.WrittenInCrayon {
		w = append(w, analyzer.Warning{
			Code:     "CERT_WEAK_KEY",
			Severity: analyzer.WrittenInCrayon,
			Title:    certPrefix(cert) + "Weak Key",
			Detail:   "Key type: " + cert.KeyType + ".",
			Why: "This key is so weak that my grandma could brute-force it " +
				"with a calculator from 1995. Get a real key.",
		})
	}

	// SHA-1 signature
	if cert.SignatureGrade == analyzer.WrittenInCrayon {
		w = append(w, analyzer.Warning{
			Code:     "CERT_SHA1",
			Severity: analyzer.WrittenInCrayon,
			Title:    certPrefix(cert) + "Insecure Signature Algorithm: " + cert.SignatureAlg,
			Detail:   "This certificate uses a signature algorithm with known weaknesses.",
			Why: "SHA-1?! Google literally created a collision attack for this in 2017. " +
				"Using this in production is professional negligence. Update. The. Cert.",
		})
	}

	// Hostname mismatch
	if cert.Role == analyzer.RoleLeaf && !cert.HostnameMatch {
		w = append(w, analyzer.Warning{
			Code:     "CERT_HOSTNAME_MISMATCH",
			Severity: analyzer.WrittenInCrayon,
			Title:    "Hostname Mismatch",
			Detail:   "The certificate does not cover the hostname you connected to.",
			Why: "The cert doesn't match the hostname. Someone installed the WRONG CERT. " +
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
			Severity: analyzer.WrittenInCrayon,
			Title:    "Missing Intermediate Certificate",
			Detail:   "The server did not send all required intermediate certificates.",
			Why: "You forgot the intermediate cert. The ENTIRE chain of trust is broken. " +
				"Half the browsers on earth can't verify this cert. How did this pass testing? DID you test?",
		})
	}

	if !chain.ChainOrderCorrect {
		w = append(w, analyzer.Warning{
			Code:     "CHAIN_WRONG_ORDER",
			Severity: analyzer.WrittenInCrayon,
			Title:    "Certificate Chain in Wrong Order",
			Detail:   "Certificates should be ordered: leaf → intermediate(s) → root.",
			Why: "The chain is in the wrong order. Did someone just throw the certs into the " +
				"config file and hope for the best? That's not how PKI works.",
		})
	}

	if chain.HasUnnecessaryRoot {
		w = append(w, analyzer.Warning{
			Code:     "CHAIN_UNNECESSARY_ROOT",
			Severity: analyzer.MallCopCredentials,
			Title:    "Unnecessary Root CA in Chain",
			Detail:   "The server is sending the root CA certificate, which clients already have.",
			Why: "You're sending the root cert. Why? The client ALREADY HAS IT. " +
				"You're just wasting bandwidth to prove you don't understand how trust stores work.",
		})
	}

	if chain.VerificationError != "" {
		w = append(w, analyzer.Warning{
			Code:     "CHAIN_VERIFICATION_FAILED",
			Severity: analyzer.WrittenInCrayon,
			Title:    "Chain Verification Failed",
			Detail:   "Trust store verification error: " + chain.VerificationError,
			Why: "Verification FAILED. The trust store looked at this chain and said 'nah.' " +
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
