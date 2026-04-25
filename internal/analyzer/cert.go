package analyzer

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"
)

// AnalyzeCert performs a full analysis of a single certificate.
func AnalyzeCert(cert *x509.Certificate, depth int, totalCerts int, targetHost string) CertAnalysis {
	analysis := CertAnalysis{
		Depth:        depth,
		Role:         determineRole(cert, depth, totalCerts),
		Subject:      cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		CommonName:   cert.Subject.CommonName,
		Organization: strings.Join(cert.Subject.Organization, ", "),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		SerialNumber: fmt.Sprintf("%X", cert.SerialNumber),
		SignatureAlg: cert.SignatureAlgorithm.String(),
		IsCA:         cert.IsCA,
		RawCert:      cert,
	}

	// DNS Names
	analysis.DNSNames = cert.DNSNames

	// IP Addresses
	for _, ip := range cert.IPAddresses {
		analysis.IPAddresses = append(analysis.IPAddresses, ip.String())
	}

	// Expiry analysis
	analysis.DaysRemaining = int(time.Until(cert.NotAfter).Hours() / 24)
	analysis.IsExpired = time.Now().After(cert.NotAfter)
	analysis.ExpiryGrade = gradeExpiry(analysis.DaysRemaining, analysis.IsExpired)

	// Signature algorithm grading
	analysis.SignatureGrade = gradeSignatureAlg(cert.SignatureAlgorithm)

	// Key type and strength
	analysis.KeyType, analysis.KeyBits = getKeyInfo(cert)
	analysis.KeyGrade = gradeKeyStrength(analysis.KeyType, analysis.KeyBits)

	// Fingerprint
	fingerprint := sha256.Sum256(cert.Raw)
	analysis.Fingerprint = fmt.Sprintf("%X", fingerprint)

	// Self-signed check
	analysis.IsSelfSigned = cert.Subject.String() == cert.Issuer.String()

	// Wildcard check
	analysis.IsWildcard = false
	for _, name := range cert.DNSNames {
		if strings.HasPrefix(name, "*.") {
			analysis.IsWildcard = true
			break
		}
	}
	if strings.HasPrefix(cert.Subject.CommonName, "*.") {
		analysis.IsWildcard = true
	}

	// Hostname match (only relevant for leaf certs)
	if depth == 0 && targetHost != "" {
		analysis.HostnameMatch = checkHostnameMatch(cert, targetHost)
	} else {
		analysis.HostnameMatch = true // Not applicable for non-leaf
	}

	// Overall grade for this cert
	analysis.OverallGrade = worstOf(analysis.ExpiryGrade, analysis.SignatureGrade, analysis.KeyGrade)
	if depth == 0 && !analysis.HostnameMatch {
		analysis.OverallGrade = WrittenInCrayon
	}
	if analysis.IsSelfSigned && depth == 0 {
		analysis.OverallGrade = worst(analysis.OverallGrade, MallCopCredentials)
	}

	return analysis
}

// determineRole identifies a certificate's role in the chain.
func determineRole(cert *x509.Certificate, depth int, totalCerts int) CertRole {
	if depth == 0 {
		return RoleLeaf
	}
	// If it's the last cert and it's self-signed, it's a root
	if depth == totalCerts-1 && cert.Subject.String() == cert.Issuer.String() {
		return RoleRoot
	}
	// If it's a CA cert but not the last, it's an intermediate
	if cert.IsCA {
		if depth == totalCerts-1 {
			return RoleRoot
		}
		return RoleIntermediate
	}
	return RoleIntermediate
}

// gradeExpiry assigns a health status based on days remaining.
func gradeExpiry(daysLeft int, isExpired bool) HealthStatus {
	if isExpired {
		return WrittenInCrayon
	}
	if daysLeft <= 14 {
		return WrittenInCrayon
	}
	if daysLeft <= 30 {
		return MallCopCredentials
	}
	return MainCharacterEnergy
}

// gradeSignatureAlg grades the signature algorithm.
func gradeSignatureAlg(alg x509.SignatureAlgorithm) HealthStatus {
	switch alg {
	case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
		x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512,
		x509.PureEd25519:
		return MainCharacterEnergy
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1:
		return WrittenInCrayon
	case x509.MD5WithRSA, x509.MD2WithRSA:
		return WrittenInCrayon
	default:
		return MallCopCredentials
	}
}

// getKeyInfo extracts key type and bit size from a certificate.
func getKeyInfo(cert *x509.Certificate) (string, int) {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		bits := pub.N.BitLen()
		return "RSA", bits
	case *ecdsa.PublicKey:
		bits := pub.Curve.Params().BitSize
		curveName := pub.Curve.Params().Name
		return fmt.Sprintf("ECDSA %s", curveName), bits
	case ed25519.PublicKey:
		return "Ed25519", 256
	default:
		return "Unknown", 0
	}
}

// gradeKeyStrength grades the key strength.
func gradeKeyStrength(keyType string, bits int) HealthStatus {
	if strings.HasPrefix(keyType, "RSA") {
		if bits < 2048 {
			return WrittenInCrayon
		}
		if bits < 4096 {
			return MainCharacterEnergy // 2048 is still fine in 2025
		}
		return MainCharacterEnergy
	}
	if strings.HasPrefix(keyType, "ECDSA") {
		if bits < 256 {
			return MallCopCredentials
		}
		return MainCharacterEnergy
	}
	if keyType == "Ed25519" {
		return MainCharacterEnergy
	}
	return MallCopCredentials
}

// checkHostnameMatch verifies if the certificate covers the target hostname.
func checkHostnameMatch(cert *x509.Certificate, hostname string) bool {
	// If hostname is an IP, check IP SANs
	if ip := net.ParseIP(hostname); ip != nil {
		for _, certIP := range cert.IPAddresses {
			if certIP.Equal(ip) {
				return true
			}
		}
		return false
	}

	// Check DNS SANs
	for _, name := range cert.DNSNames {
		if matchHostname(name, hostname) {
			return true
		}
	}

	// Fall back to CN (deprecated but still common)
	if matchHostname(cert.Subject.CommonName, hostname) {
		return true
	}

	return false
}

// matchHostname checks if a certificate name matches a hostname,
// supporting wildcard matching.
func matchHostname(pattern, hostname string) bool {
	pattern = strings.ToLower(pattern)
	hostname = strings.ToLower(hostname)

	if pattern == hostname {
		return true
	}

	// Wildcard matching: *.example.com matches foo.example.com
	// but NOT foo.bar.example.com
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		if strings.HasSuffix(hostname, suffix) {
			// Make sure there's only one level of subdomain
			prefix := hostname[:len(hostname)-len(suffix)]
			if !strings.Contains(prefix, ".") && len(prefix) > 0 {
				return true
			}
		}
	}

	return false
}

// worstOf returns the worst health status from a list.
func worstOf(statuses ...HealthStatus) HealthStatus {
	result := MainCharacterEnergy
	for _, s := range statuses {
		if s > result {
			result = s
		}
	}
	return result
}

// worst returns the worse of two health statuses.
func worst(a, b HealthStatus) HealthStatus {
	if a > b {
		return a
	}
	return b
}
