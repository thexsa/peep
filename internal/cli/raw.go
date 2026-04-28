package cli

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/thexsa/peep/internal/analyzer"
	"github.com/thexsa/peep/internal/ui"
)

// renderRawX509 prints raw x509 text output for each cert in the chain,
// similar to `openssl x509 -text -noout`.
func renderRawX509(chain analyzer.ChainAnalysis) {
	for _, cert := range chain.Certificates {
		fmt.Println(renderSingleRawX509(cert))
	}
}

// renderSingleRawX509 formats a single certificate's raw x509 fields.
func renderSingleRawX509(cert analyzer.CertAnalysis) string {
	raw := cert.RawCert
	if raw == nil {
		return ""
	}

	name := cert.CommonName
	if name == "" {
		name = cert.Subject
	}

	var lines []string
	lines = append(lines, ui.Theme.BoldStyle.Render(
		fmt.Sprintf("RAW X.509  [%d] %s  (%s)", cert.Depth, name, cert.Role)))
	lines = append(lines, "")

	// Certificate version
	lines = append(lines, rawKV("Version", fmt.Sprintf("%d (0x%x)", raw.Version, raw.Version-1)))

	// Serial number
	lines = append(lines, rawKV("Serial Number", formatSerialColon(raw.SerialNumber.Bytes())))

	// Signature Algorithm
	lines = append(lines, rawKV("Signature Algorithm", raw.SignatureAlgorithm.String()))

	// Issuer
	lines = append(lines, rawKV("Issuer", raw.Issuer.String()))

	// Validity
	lines = append(lines, rawKV("Not Before", raw.NotBefore.Format("Jan 02 15:04:05 2006 MST")))
	lines = append(lines, rawKV("Not After", raw.NotAfter.Format("Jan 02 15:04:05 2006 MST")))

	// Subject
	lines = append(lines, rawKV("Subject", raw.Subject.String()))

	// Public Key Info
	lines = append(lines, "")
	lines = append(lines, ui.Theme.BoldStyle.Render("  Subject Public Key Info:"))
	lines = append(lines, rawPublicKeyInfo(raw)...)

	// X509v3 Extensions
	lines = append(lines, "")
	lines = append(lines, ui.Theme.BoldStyle.Render("  X509v3 Extensions:"))
	lines = append(lines, rawExtensions(raw)...)

	return ui.ApplyBorder(lines, ui.CardBorder)
}

// rawKV formats a key-value pair for raw output with 22-char key width.
func rawKV(key, value string) string {
	return fmt.Sprintf("  %-22s %s", key+":", ui.Theme.MutedStyle.Render(value))
}

// formatSerialColon formats serial number bytes as colon-separated hex.
func formatSerialColon(b []byte) string {
	h := hex.EncodeToString(b)
	var parts []string
	for i := 0; i < len(h); i += 2 {
		end := i + 2
		if end > len(h) {
			end = len(h)
		}
		parts = append(parts, h[i:end])
	}
	return strings.Join(parts, ":")
}

// rawPublicKeyInfo renders the public key section.
func rawPublicKeyInfo(cert *x509.Certificate) []string {
	var lines []string
	indent := "    "

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		bits := pub.N.BitLen()
		lines = append(lines, fmt.Sprintf("%s%s", indent,
			ui.Theme.MutedStyle.Render(fmt.Sprintf("Algorithm: RSA"))))
		lines = append(lines, fmt.Sprintf("%s%s", indent,
			ui.Theme.MutedStyle.Render(fmt.Sprintf("Key Size: %d bits", bits))))
		lines = append(lines, fmt.Sprintf("%s%s", indent,
			ui.Theme.MutedStyle.Render(fmt.Sprintf("Exponent: %d", pub.E))))
	case *ecdsa.PublicKey:
		curveName := pub.Curve.Params().Name
		bits := pub.Curve.Params().BitSize
		lines = append(lines, fmt.Sprintf("%s%s", indent,
			ui.Theme.MutedStyle.Render(fmt.Sprintf("Algorithm: ECDSA"))))
		lines = append(lines, fmt.Sprintf("%s%s", indent,
			ui.Theme.MutedStyle.Render(fmt.Sprintf("Curve: %s (%d bits)", curveName, bits))))
	case ed25519.PublicKey:
		lines = append(lines, fmt.Sprintf("%s%s", indent,
			ui.Theme.MutedStyle.Render("Algorithm: Ed25519 (256 bits)")))
	default:
		lines = append(lines, fmt.Sprintf("%s%s", indent,
			ui.Theme.MutedStyle.Render("Algorithm: Unknown")))
	}

	return lines
}

// rawExtensions renders the x509v3 extensions section.
func rawExtensions(cert *x509.Certificate) []string {
	var lines []string
	indent := "    "

	// Basic Constraints
	if cert.BasicConstraintsValid {
		val := fmt.Sprintf("CA:%t", cert.IsCA)
		if cert.MaxPathLen > 0 || cert.MaxPathLenZero {
			val += fmt.Sprintf(", pathlen:%d", cert.MaxPathLen)
		}
		lines = append(lines, fmt.Sprintf("%s%s", indent,
			ui.Theme.BoldStyle.Render("X509v3 Basic Constraints:")))
		lines = append(lines, fmt.Sprintf("%s  %s", indent,
			ui.Theme.MutedStyle.Render(val)))
	}

	// Key Usage
	if cert.KeyUsage != 0 {
		usages := formatKeyUsage(cert.KeyUsage)
		lines = append(lines, fmt.Sprintf("%s%s", indent,
			ui.Theme.BoldStyle.Render("X509v3 Key Usage:")))
		lines = append(lines, fmt.Sprintf("%s  %s", indent,
			ui.Theme.MutedStyle.Render(usages)))
	}

	// Extended Key Usage
	if len(cert.ExtKeyUsage) > 0 {
		var ekuNames []string
		for _, eku := range cert.ExtKeyUsage {
			ekuNames = append(ekuNames, formatExtKeyUsage(eku))
		}
		lines = append(lines, fmt.Sprintf("%s%s", indent,
			ui.Theme.BoldStyle.Render("X509v3 Extended Key Usage:")))
		lines = append(lines, fmt.Sprintf("%s  %s", indent,
			ui.Theme.MutedStyle.Render(strings.Join(ekuNames, ", "))))
	}

	// Subject Alternative Name
	if len(cert.DNSNames) > 0 || len(cert.IPAddresses) > 0 || len(cert.EmailAddresses) > 0 {
		lines = append(lines, fmt.Sprintf("%s%s", indent,
			ui.Theme.BoldStyle.Render("X509v3 Subject Alternative Name:")))
		var sans []string
		for _, dns := range cert.DNSNames {
			sans = append(sans, "DNS:"+dns)
		}
		for _, ip := range cert.IPAddresses {
			sans = append(sans, "IP:"+ip.String())
		}
		for _, email := range cert.EmailAddresses {
			sans = append(sans, "email:"+email)
		}

		// Word-wrap SANs
		sanStr := strings.Join(sans, ", ")
		sanW := ui.ContentWidth(6)
		sanIndent := indent + "  "
		wrapped := ui.WrapText(sanStr, sanIndent, sanW)
		for _, line := range wrapped {
			lines = append(lines, fmt.Sprintf("%s%s", sanIndent,
				ui.Theme.MutedStyle.Render(line)))
		}
	}

	// Authority Key Identifier
	if len(cert.AuthorityKeyId) > 0 {
		lines = append(lines, fmt.Sprintf("%s%s", indent,
			ui.Theme.BoldStyle.Render("X509v3 Authority Key Identifier:")))
		lines = append(lines, fmt.Sprintf("%s  %s", indent,
			ui.Theme.MutedStyle.Render(formatKeyID(cert.AuthorityKeyId))))
	}

	// Subject Key Identifier
	if len(cert.SubjectKeyId) > 0 {
		lines = append(lines, fmt.Sprintf("%s%s", indent,
			ui.Theme.BoldStyle.Render("X509v3 Subject Key Identifier:")))
		lines = append(lines, fmt.Sprintf("%s  %s", indent,
			ui.Theme.MutedStyle.Render(formatKeyID(cert.SubjectKeyId))))
	}

	// CRL Distribution Points
	if len(cert.CRLDistributionPoints) > 0 {
		lines = append(lines, fmt.Sprintf("%s%s", indent,
			ui.Theme.BoldStyle.Render("X509v3 CRL Distribution Points:")))
		for _, dp := range cert.CRLDistributionPoints {
			lines = append(lines, fmt.Sprintf("%s  %s", indent,
				ui.Theme.MutedStyle.Render(dp)))
		}
	}

	// Authority Information Access (OCSP + CA Issuers)
	if len(cert.OCSPServer) > 0 || len(cert.IssuingCertificateURL) > 0 {
		lines = append(lines, fmt.Sprintf("%s%s", indent,
			ui.Theme.BoldStyle.Render("Authority Information Access:")))
		for _, ocsp := range cert.OCSPServer {
			lines = append(lines, fmt.Sprintf("%s  %s", indent,
				ui.Theme.MutedStyle.Render("OCSP - URI:"+ocsp)))
		}
		for _, caIssuer := range cert.IssuingCertificateURL {
			lines = append(lines, fmt.Sprintf("%s  %s", indent,
				ui.Theme.MutedStyle.Render("CA Issuers - URI:"+caIssuer)))
		}
	}

	if len(lines) == 0 {
		lines = append(lines, fmt.Sprintf("%s%s", indent,
			ui.Theme.MutedStyle.Render("(none)")))
	}

	return lines
}

// formatKeyUsage converts a KeyUsage bitmask to human-readable names.
func formatKeyUsage(ku x509.KeyUsage) string {
	var usages []string
	mapping := []struct {
		flag x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "Digital Signature"},
		{x509.KeyUsageContentCommitment, "Content Commitment"},
		{x509.KeyUsageKeyEncipherment, "Key Encipherment"},
		{x509.KeyUsageDataEncipherment, "Data Encipherment"},
		{x509.KeyUsageKeyAgreement, "Key Agreement"},
		{x509.KeyUsageCertSign, "Certificate Sign"},
		{x509.KeyUsageCRLSign, "CRL Sign"},
		{x509.KeyUsageEncipherOnly, "Encipher Only"},
		{x509.KeyUsageDecipherOnly, "Decipher Only"},
	}
	for _, m := range mapping {
		if ku&m.flag != 0 {
			usages = append(usages, m.name)
		}
	}
	return strings.Join(usages, ", ")
}

// formatExtKeyUsage converts an ExtKeyUsage to a human-readable name.
func formatExtKeyUsage(eku x509.ExtKeyUsage) string {
	switch eku {
	case x509.ExtKeyUsageAny:
		return "Any"
	case x509.ExtKeyUsageServerAuth:
		return "TLS Web Server Authentication"
	case x509.ExtKeyUsageClientAuth:
		return "TLS Web Client Authentication"
	case x509.ExtKeyUsageCodeSigning:
		return "Code Signing"
	case x509.ExtKeyUsageEmailProtection:
		return "E-mail Protection"
	case x509.ExtKeyUsageTimeStamping:
		return "Time Stamping"
	case x509.ExtKeyUsageOCSPSigning:
		return "OCSP Signing"
	default:
		return fmt.Sprintf("Unknown (%d)", eku)
	}
}

// formatKeyID formats a key identifier as colon-separated hex.
func formatKeyID(id []byte) string {
	h := hex.EncodeToString(id)
	var parts []string
	for i := 0; i < len(h); i += 2 {
		end := i + 2
		if end > len(h) {
			end = len(h)
		}
		parts = append(parts, strings.ToUpper(h[i:end]))
	}
	return strings.Join(parts, ":")
}
