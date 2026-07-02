package analyzer

import (
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const maxCRLSize = 10 * 1024 * 1024 // 10 MB

// CRLResult holds the result of a CRL revocation check.
type CRLResult struct {
	Available       bool      `json:"available"`
	Fetched         bool      `json:"fetched"`
	FetchError      string    `json:"fetch_error,omitempty"`
	IsRevoked       bool      `json:"is_revoked"`
	RevokedAt       time.Time `json:"revoked_at,omitempty"`
	RevokeReason    string    `json:"revoke_reason,omitempty"`
	ThisUpdate      time.Time `json:"this_update,omitempty"`
	NextUpdate      time.Time `json:"next_update,omitempty"`
	IsStale         bool      `json:"is_stale"`
	CRLEndpoint     string    `json:"crl_endpoint,omitempty"`
	CRLSize         int       `json:"crl_size"`
	EntryCount      int       `json:"entry_count"`
	IsLDAP          bool      `json:"is_ldap,omitempty"`           // True if the CRL endpoint is LDAP
	LDAPEndpoint    string    `json:"ldap_endpoint,omitempty"`     // The LDAP URI for display
	AllEndpoints    []string  `json:"all_endpoints,omitempty"`     // All CRL distribution point URIs
	SkippedLDAP     []string  `json:"skipped_ldap,omitempty"`      // LDAP URIs that were skipped
}

// CheckCRL performs a CRL revocation check for the given certificate.
// It iterates through all CRL distribution points:
//   - HTTP/HTTPS endpoints are fetched and checked
//   - LDAP endpoints are noted but not fetched (Go has no native LDAP support)
//
// The first successful HTTP fetch is used for the revocation check.
func CheckCRL(cert *x509.Certificate, issuer *x509.Certificate, timeout time.Duration) CRLResult {
	if len(cert.CRLDistributionPoints) == 0 {
		return CRLResult{Available: false}
	}

	result := CRLResult{
		Available:    true,
		AllEndpoints: cert.CRLDistributionPoints,
	}

	// Categorize endpoints and try HTTP ones
	for _, endpoint := range cert.CRLDistributionPoints {
		if isLDAPEndpoint(endpoint) {
			result.SkippedLDAP = append(result.SkippedLDAP, endpoint)
			continue
		}

		if !isHTTPEndpoint(endpoint) {
			// Unknown scheme — skip
			continue
		}

		// Try this HTTP endpoint
		fetchResult := fetchAndCheckCRL(cert, issuer, endpoint, timeout)
		if fetchResult.Fetched {
			// Success — use this result
			fetchResult.Available = true
			fetchResult.AllEndpoints = result.AllEndpoints
			fetchResult.SkippedLDAP = result.SkippedLDAP
			return fetchResult
		}

		// HTTP fetch failed — record the error but try next endpoint
		if result.FetchError == "" {
			result.CRLEndpoint = endpoint
			result.FetchError = fetchResult.FetchError
		}
	}

	// No HTTP endpoint succeeded
	if len(result.SkippedLDAP) > 0 && result.CRLEndpoint == "" {
		// Only LDAP endpoints available
		result.IsLDAP = true
		result.LDAPEndpoint = result.SkippedLDAP[0]
		result.CRLEndpoint = result.SkippedLDAP[0]
	}

	return result
}

// fetchAndCheckCRL fetches a CRL from an HTTP endpoint, verifies the
// signature against the issuer, and checks if the cert is revoked.
func fetchAndCheckCRL(cert *x509.Certificate, issuer *x509.Certificate, endpoint string, timeout time.Duration) CRLResult {
	result := CRLResult{
		CRLEndpoint: endpoint,
	}

	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(endpoint)
	if err != nil {
		errMsg := err.Error()
		if isHTTPS(endpoint) {
			result.FetchError = fmt.Sprintf("CRL endpoint TLS error: %s", errMsg)
		} else {
			result.FetchError = errMsg
		}
		return result
	}
	defer resp.Body.Close()

	crlBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxCRLSize))
	if err != nil {
		result.FetchError = fmt.Sprintf("failed to read CRL response: %s", err)
		return result
	}
	result.Fetched = true
	result.CRLSize = len(crlBytes)

	// Parse CRL.
	revocationList, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		result.FetchError = fmt.Sprintf("failed to parse CRL: %s", err)
		return result
	}

	// Verify CRL signature against issuer.
	if err := revocationList.CheckSignatureFrom(issuer); err != nil {
		result.FetchError = fmt.Sprintf("CRL signature verification failed: %s", err)
		return result
	}

	// Populate timing fields.
	result.ThisUpdate = revocationList.ThisUpdate
	result.NextUpdate = revocationList.NextUpdate
	result.EntryCount = len(revocationList.RevokedCertificateEntries)

	// Check freshness.
	if !revocationList.NextUpdate.IsZero() && revocationList.NextUpdate.Before(time.Now()) {
		result.IsStale = true
	}

	// Search for the leaf's serial in the revoked entries.
	for _, entry := range revocationList.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			result.IsRevoked = true
			result.RevokedAt = entry.RevocationTime
			result.RevokeReason = revokeReasonText(int(entry.ReasonCode))
			break
		}
	}

	return result
}

// isHTTPS reports whether a URL starts with https://.
func isHTTPS(url string) bool {
	return len(url) >= 8 && strings.EqualFold(url[:8], "https://")
}

// isHTTPEndpoint reports whether a URL starts with http:// or https://.
func isHTTPEndpoint(url string) bool {
	lower := strings.ToLower(url)
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}

// isLDAPEndpoint reports whether a URL starts with ldap:// or ldaps://.
func isLDAPEndpoint(url string) bool {
	lower := strings.ToLower(url)
	return strings.HasPrefix(lower, "ldap://") || strings.HasPrefix(lower, "ldaps://")
}

// LDAPSearchCommand generates an ldapsearch command for querying a CRL
// from an LDAP distribution point (typically Microsoft AD CS).
func LDAPSearchCommand(ldapURI string) string {
	// The LDAP URI already contains the full query — ldapsearch can use it directly
	return fmt.Sprintf("ldapsearch -x -H \"%s\" -s base certificateRevocationList", ldapURI)
}
