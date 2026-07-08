package analyzer

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"net"
	"strings"
)

// CAOriginResult holds the confidence scoring result for CA origin detection.
type CAOriginResult struct {
	Score      int                `json:"score"`
	Assessment string            `json:"assessment"` // "public_ca", "very_likely_private_ca", "likely_private_ca", "possibly_private_ca", "unknown"
	Evidence   []CAOriginEvidence `json:"evidence"`
}

// CAOriginEvidence records a single scoring factor with its point value.
type CAOriginEvidence struct {
	Factor string `json:"factor"`
	Points int    `json:"points"`
	Detail string `json:"detail"`
}

// Well-known CA/B Forum policy OIDs.
var cabForumPolicyOIDs = map[string]string{
	"2.23.140.1.2.1": "CA/B Forum Domain Validated (DV)",
	"2.23.140.1.2.2": "CA/B Forum Organization Validated (OV)",
	"2.23.140.1.2.3": "CA/B Forum Individual Validated (IV)",
	"2.23.140.1.1":   "CA/B Forum Extended Validation (EV)",
	"2.23.140.1.3":   "CA/B Forum Code Signing",
}

// Internal domain TLDs and suffixes that strongly indicate private infrastructure.
var internalDomainSuffixes = []string{
	".local", ".internal", ".corp", ".lan", ".home", ".private",
	".intranet", ".ad", ".domain", ".test", ".example", ".invalid",
	".localhost",
}

// Keywords in issuer/subject CN or O that suggest internal CAs.
var internalCAKeywords = []string{
	"internal", "corp", "enterprise", "adcs", "ad cs",
	"issuing ca", "issuingca", "root ca", "rootca",
	"subordinate ca", "policy ca", "private",
}

// Known public CA organization names (partial match).
var publicCABrands = []string{
	"digicert", "let's encrypt", "globalsign", "comodo", "sectigo",
	"godaddy", "entrust", "verisign", "thawte", "geotrust",
	"rapidssl", "amazon", "google trust", "microsoft", "apple",
	"certum", "buypass", "trustwave", "usertrust", "starfield",
	"baltimore", "actalis", "quo vadis", "ssl.com", "zerossl",
}

// DetectCAOrigin analyzes the certificate chain and leaf cert to determine
// whether the CA is public or private/internal, using a confidence scoring system.
func DetectCAOrigin(chain ChainAnalysis, leaf *x509.Certificate, hasEmbeddedSCTs bool) CAOriginResult {
	result := CAOriginResult{}

	if leaf == nil {
		result.Assessment = "unknown"
		return result
	}

	// Factor 1: Trust store validation
	// Key insight: the system trust store on macOS/Windows can contain
	// enterprise-pushed internal root CAs (via MDM/GPO). So chain validation
	// alone does NOT mean the CA is public. We must check if the trusted root
	// matches a known public CA brand.
	if chain.TrustStoreVerified {
		rootLower := strings.ToLower(chain.TrustedRootName)
		isKnownPublicCA := false
		for _, brand := range publicCABrands {
			if strings.Contains(rootLower, brand) {
				isKnownPublicCA = true
				break
			}
		}

		if isKnownPublicCA {
			// Root is a recognized public CA — strong signal this is NOT private
			result.Evidence = append(result.Evidence, CAOriginEvidence{
				Factor: "Trust Store",
				Points: -80,
				Detail: fmt.Sprintf("Chain validates to known public CA root (%s)", chain.TrustedRootName),
			})
		} else {
			// Chain validates against the system store, but the root is not a
			// recognized public CA. This is common for enterprise environments
			// where internal CAs are pushed into the system trust store via MDM.
			// Neutral score — validation is expected for both public and properly
			// deployed internal CAs.
			result.Evidence = append(result.Evidence, CAOriginEvidence{
				Factor: "Trust Store",
				Points: 0,
				Detail: fmt.Sprintf("Chain validates to system trust store, but root is not a recognized public CA (%s)", chain.TrustedRootName),
			})
		}
	} else if !chain.HasMissingIntermediate && !chain.LeafOnlyMissingIntermediate &&
		chain.VerificationError != "" && !strings.Contains(chain.VerificationError, "incomplete chain") {
		result.Evidence = append(result.Evidence, CAOriginEvidence{
			Factor: "Trust Store",
			Points: 50,
			Detail: "Chain terminates at non-public root (complete chain, unknown root CA)",
		})
	}

	// Factor 2: AIA/CDP contains LDAP, internal domains, RFC1918 addresses
	aiaScore, aiaEvidence := scoreAIACDP(leaf)
	if aiaScore != 0 {
		result.Evidence = append(result.Evidence, aiaEvidence)
	}

	// Factor 3: Issuer/Subject DN contains internal markers
	dnScore, dnEvidence := scoreIssuerDN(leaf)
	if dnScore != 0 {
		result.Evidence = append(result.Evidence, dnEvidence)
	}

	// Factor 4: SAN/CN contains internal names
	sanScore, sanEvidence := scoreSANs(leaf)
	if sanScore != 0 {
		result.Evidence = append(result.Evidence, sanEvidence)
	}

	// Factor 5: Certificate policy OIDs
	policyScore, policyEvidence := scorePolicyOIDs(leaf)
	if policyScore != 0 {
		result.Evidence = append(result.Evidence, policyEvidence)
	}

	// Factor 6: No embedded SCTs
	if !hasEmbeddedSCTs {
		result.Evidence = append(result.Evidence, CAOriginEvidence{
			Factor: "Certificate Transparency",
			Points: 10,
			Detail: "No embedded SCTs observed",
		})
	}

	// Factor 7: Public CA branding with policy OIDs (negative signal)
	brandScore, brandEvidence := scorePublicBranding(leaf)
	if brandScore != 0 {
		result.Evidence = append(result.Evidence, brandEvidence)
	}

	// Calculate total score
	for _, e := range result.Evidence {
		result.Score += e.Points
	}

	// Determine assessment based on score.
	// Known public CA roots get -80 points. Unknown roots in the system store
	// get 0 (enterprise roots pushed via MDM validate but aren't public).
	// Internal signals (LDAP URIs, internal keywords, private IPs, no SCTs)
	// push the score positive. Public signals (public branding + CAB OIDs)
	// push the score negative.
	switch {
	case result.Score >= 80:
		result.Assessment = "very_likely_private_ca"
	case result.Score >= 40:
		result.Assessment = "likely_private_ca"
	case result.Score >= 15:
		result.Assessment = "possibly_private_ca"
	case result.Score <= -40:
		result.Assessment = "public_ca"
	default:
		result.Assessment = "unknown"
	}

	return result
}

// scoreAIACDP checks AIA and CRL Distribution Point URIs for internal infrastructure indicators.
func scoreAIACDP(cert *x509.Certificate) (int, CAOriginEvidence) {
	var allURIs []string
	allURIs = append(allURIs, cert.CRLDistributionPoints...)
	allURIs = append(allURIs, cert.IssuingCertificateURL...)
	allURIs = append(allURIs, cert.OCSPServer...)

	var reasons []string

	for _, uri := range allURIs {
		lower := strings.ToLower(uri)

		// LDAP URIs are a dead giveaway for Microsoft AD CS
		if strings.HasPrefix(lower, "ldap://") || strings.HasPrefix(lower, "ldap:///") {
			reasons = append(reasons, "LDAP URI: "+truncateStr(uri, 60))
			continue
		}

		// Check for internal domain patterns in HTTP URIs
		for _, suffix := range internalDomainSuffixes {
			if strings.Contains(lower, suffix+"/") || strings.HasSuffix(lower, suffix) {
				reasons = append(reasons, fmt.Sprintf("Internal domain (%s): %s", suffix, truncateStr(uri, 60)))
				break
			}
		}

		// Check for AD CS CertEnroll path
		if strings.Contains(lower, "certenroll") || strings.Contains(lower, "certsrv") {
			reasons = append(reasons, "AD CS path (CertEnroll/CertSrv): "+truncateStr(uri, 60))
		}

		// Check for RFC1918 private IP addresses
		if containsPrivateIP(uri) {
			reasons = append(reasons, "Private IP address: "+truncateStr(uri, 60))
		}

		// Check for shortnames (hostnames without dots)
		host := extractHostFromURI(uri)
		if host != "" && !strings.Contains(host, ".") && net.ParseIP(host) == nil {
			reasons = append(reasons, "Shortname (no FQDN): "+host)
		}
	}

	if len(reasons) == 0 {
		return 0, CAOriginEvidence{}
	}

	// Cap at +40
	detail := strings.Join(reasons, "; ")
	if len(detail) > 120 {
		detail = fmt.Sprintf("%d internal infrastructure indicator(s) in AIA/CDP URIs", len(reasons))
	}
	return 40, CAOriginEvidence{
		Factor: "AIA/CDP URIs",
		Points: 40,
		Detail: detail,
	}
}

// scoreIssuerDN checks issuer and subject distinguished names for internal CA markers.
func scoreIssuerDN(cert *x509.Certificate) (int, CAOriginEvidence) {
	searchTargets := []string{
		strings.ToLower(cert.Issuer.CommonName),
		strings.ToLower(strings.Join(cert.Issuer.Organization, " ")),
		strings.ToLower(cert.Subject.CommonName),
	}

	// Also check Domain Components (DC=)
	for _, name := range cert.Issuer.Names {
		if name.Type.Equal(asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}) { // DC OID
			if s, ok := name.Value.(string); ok {
				searchTargets = append(searchTargets, strings.ToLower(s))
			}
		}
	}

	var matches []string
	combined := strings.Join(searchTargets, " ")

	for _, kw := range internalCAKeywords {
		if strings.Contains(combined, kw) {
			matches = append(matches, kw)
		}
	}

	// Check for internal domain components
	for _, suffix := range []string{"local", "corp", "internal", "ad", "domain"} {
		for _, name := range cert.Issuer.Names {
			if name.Type.Equal(asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}) {
				if s, ok := name.Value.(string); ok && strings.EqualFold(s, suffix) {
					matches = append(matches, "DC="+s)
				}
			}
		}
	}

	if len(matches) == 0 {
		return 0, CAOriginEvidence{}
	}

	return 30, CAOriginEvidence{
		Factor: "Issuer/Subject DN",
		Points: 30,
		Detail: fmt.Sprintf("Contains internal markers: %s (Issuer: %s)", strings.Join(matches, ", "), cert.Issuer.CommonName),
	}
}

// scoreSANs checks Subject Alternative Names for internal/private indicators.
func scoreSANs(cert *x509.Certificate) (int, CAOriginEvidence) {
	var reasons []string

	// Check DNS names for internal suffixes and shortnames
	for _, name := range cert.DNSNames {
		lower := strings.ToLower(name)
		for _, suffix := range internalDomainSuffixes {
			if strings.HasSuffix(lower, suffix) {
				reasons = append(reasons, name)
				break
			}
		}
		// Shortname (no dots = not FQDN)
		if !strings.Contains(name, ".") {
			reasons = append(reasons, name+" (shortname)")
		}
	}

	// Check CN for internal patterns
	cn := strings.ToLower(cert.Subject.CommonName)
	for _, suffix := range internalDomainSuffixes {
		if strings.HasSuffix(cn, suffix) {
			reasons = append(reasons, cert.Subject.CommonName+" (CN)")
			break
		}
	}
	if cn != "" && !strings.Contains(cn, ".") && !strings.Contains(cn, " ") {
		reasons = append(reasons, cert.Subject.CommonName+" (CN shortname)")
	}

	// Check IP SANs for private addresses
	for _, ip := range cert.IPAddresses {
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			reasons = append(reasons, ip.String()+" (private IP)")
		}
	}

	if len(reasons) == 0 {
		return 0, CAOriginEvidence{}
	}

	detail := strings.Join(reasons, ", ")
	if len(detail) > 120 {
		detail = fmt.Sprintf("%d internal name(s) or private address(es) in SAN/CN", len(reasons))
	}
	return 25, CAOriginEvidence{
		Factor: "SAN/CN Names",
		Points: 25,
		Detail: detail,
	}
}

// scorePolicyOIDs checks certificate policies for CA/B Forum vs enterprise OIDs.
func scorePolicyOIDs(cert *x509.Certificate) (int, CAOriginEvidence) {
	hasCabOID := false
	hasEnterpriseOID := false
	var cabOIDNames []string
	var enterpriseOIDs []string

	for _, oid := range cert.PolicyIdentifiers {
		oidStr := oid.String()
		if name, ok := cabForumPolicyOIDs[oidStr]; ok {
			hasCabOID = true
			cabOIDNames = append(cabOIDNames, name)
		}
		// Enterprise OIDs typically start with 1.3.6.1.4.1 (private enterprise arc)
		if strings.HasPrefix(oidStr, "1.3.6.1.4.1.") {
			hasEnterpriseOID = true
			enterpriseOIDs = append(enterpriseOIDs, oidStr)
		}
	}

	if !hasCabOID && hasEnterpriseOID {
		return 20, CAOriginEvidence{
			Factor: "Certificate Policies",
			Points: 20,
			Detail: fmt.Sprintf("No CA/B Forum policy OIDs; has enterprise OID(s): %s", strings.Join(enterpriseOIDs, ", ")),
		}
	}
	if !hasCabOID && len(cert.PolicyIdentifiers) == 0 {
		return 20, CAOriginEvidence{
			Factor: "Certificate Policies",
			Points: 20,
			Detail: "No certificate policy OIDs present (no CA/B Forum compliance assertion)",
		}
	}

	return 0, CAOriginEvidence{}
}

// scorePublicBranding checks for public CA branding combined with policy OIDs (negative signal).
func scorePublicBranding(cert *x509.Certificate) (int, CAOriginEvidence) {
	hasCabOID := false
	for _, oid := range cert.PolicyIdentifiers {
		if _, ok := cabForumPolicyOIDs[oid.String()]; ok {
			hasCabOID = true
			break
		}
	}

	if !hasCabOID {
		return 0, CAOriginEvidence{}
	}

	issuerOrg := strings.ToLower(strings.Join(cert.Issuer.Organization, " "))
	issuerCN := strings.ToLower(cert.Issuer.CommonName)
	combined := issuerOrg + " " + issuerCN

	for _, brand := range publicCABrands {
		if strings.Contains(combined, brand) {
			return -40, CAOriginEvidence{
				Factor: "Public CA Branding",
				Points: -40,
				Detail: fmt.Sprintf("CA/B Forum policy OID present with public CA branding (%s)", brand),
			}
		}
	}

	return 0, CAOriginEvidence{}
}

// --- Helpers ---

// containsPrivateIP checks if a URI string contains an RFC1918 or other private IP.
func containsPrivateIP(uri string) bool {
	host := extractHostFromURI(uri)
	if host == "" {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

// extractHostFromURI pulls the hostname/IP from a URI.
func extractHostFromURI(uri string) string {
	// Strip scheme
	for _, prefix := range []string{"https://", "http://", "ldap://", "ldaps://", "ldap:///"} {
		uri = strings.TrimPrefix(uri, prefix)
	}
	// Strip path
	if idx := strings.Index(uri, "/"); idx >= 0 {
		uri = uri[:idx]
	}
	// Strip port
	host, _, err := net.SplitHostPort(uri)
	if err != nil {
		return uri
	}
	return host
}

// truncateStr shortens a string for display.
func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	half := (maxLen - 3) / 2
	return s[:half] + "..." + s[len(s)-half:]
}
