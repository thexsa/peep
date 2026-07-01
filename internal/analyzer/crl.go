package analyzer

import (
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"time"
)

const maxCRLSize = 10 * 1024 * 1024 // 10 MB

// CRLResult holds the result of a CRL revocation check.
type CRLResult struct {
	Available    bool      `json:"available"`
	Fetched      bool      `json:"fetched"`
	FetchError   string    `json:"fetch_error,omitempty"`
	IsRevoked    bool      `json:"is_revoked"`
	RevokedAt    time.Time `json:"revoked_at,omitempty"`
	RevokeReason string    `json:"revoke_reason,omitempty"`
	ThisUpdate   time.Time `json:"this_update,omitempty"`
	NextUpdate   time.Time `json:"next_update,omitempty"`
	IsStale      bool      `json:"is_stale"`
	CRLEndpoint  string    `json:"crl_endpoint,omitempty"`
	CRLSize      int       `json:"crl_size"`
	EntryCount   int       `json:"entry_count"`
}

// CheckCRL performs a CRL revocation check for the given certificate.
// It fetches the CRL from the first distribution point, verifies
// it against the issuer, and checks whether the leaf cert is revoked.
func CheckCRL(cert *x509.Certificate, issuer *x509.Certificate, timeout time.Duration) CRLResult {
	if len(cert.CRLDistributionPoints) == 0 {
		return CRLResult{Available: false}
	}

	crlEndpoint := cert.CRLDistributionPoints[0]
	result := CRLResult{
		Available:   true,
		CRLEndpoint: crlEndpoint,
	}

	// Fetch CRL with timeout and size limit.
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(crlEndpoint)
	if err != nil {
		errMsg := err.Error()
		// Surface TLS-specific errors for HTTPS endpoints.
		if isHTTPS(crlEndpoint) {
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
	return len(url) >= 8 && url[:8] == "https://"
}
