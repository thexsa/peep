package analyzer

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"time"

	"golang.org/x/crypto/ocsp"
)

// OCSPStapleResult holds the result of checking the stapled OCSP response.
type OCSPStapleResult struct {
	Present       bool       `json:"present"`
	Status        OCSPStatus `json:"status"`
	StatusText    string     `json:"status_text"`
	ProducedAt    time.Time  `json:"produced_at,omitempty"`
	ThisUpdate    time.Time  `json:"this_update,omitempty"`
	NextUpdate    time.Time  `json:"next_update,omitempty"`
	IsStale       bool       `json:"is_stale"`
	HasMustStaple bool       `json:"has_must_staple"`
	Error         string     `json:"error,omitempty"`
}

// CheckOCSPStaple inspects the OCSP response stapled to the TLS handshake.
// It parses the response, verifies it against the issuer, and checks freshness.
// The leaf certificate is used to detect the Must-Staple extension (RFC 7633).
func CheckOCSPStaple(state *tls.ConnectionState, issuer *x509.Certificate, leaf *x509.Certificate) OCSPStapleResult {
	mustStaple := hasMustStaple(leaf)

	if len(state.OCSPResponse) == 0 {
		return OCSPStapleResult{
			Present:       false,
			StatusText:    "No OCSP response stapled to handshake",
			HasMustStaple: mustStaple,
		}
	}

	resp, err := ocsp.ParseResponse(state.OCSPResponse, issuer)
	if err != nil {
		return OCSPStapleResult{
			Present:       true,
			Status:        OCSPError,
			StatusText:    "Failed to parse stapled OCSP response",
			HasMustStaple: mustStaple,
			Error:         err.Error(),
		}
	}

	result := OCSPStapleResult{
		Present:       true,
		ProducedAt:    resp.ProducedAt,
		ThisUpdate:    resp.ThisUpdate,
		NextUpdate:    resp.NextUpdate,
		HasMustStaple: mustStaple,
	}

	// Check freshness.
	if !resp.NextUpdate.IsZero() && resp.NextUpdate.Before(time.Now()) {
		result.IsStale = true
	}

	switch resp.Status {
	case ocsp.Good:
		result.Status = OCSPGood
		result.StatusText = "Good — stapled OCSP response confirms certificate is valid"
	case ocsp.Revoked:
		result.Status = OCSPRevoked
		result.StatusText = "REVOKED — stapled OCSP response indicates certificate is revoked!"
	case ocsp.Unknown:
		result.Status = OCSPUnknown
		result.StatusText = "Unknown — stapled OCSP response status is unknown"
	default:
		result.Status = OCSPError
		result.StatusText = fmt.Sprintf("Unexpected stapled OCSP status: %d", resp.Status)
	}

	return result
}

// hasMustStaple checks whether a certificate has the OCSP Must-Staple
// extension (RFC 7633). This is the TLS Feature extension (OID 1.3.6.1.5.5.7.1.24)
// with value 5 (status_request / OCSP stapling).
func hasMustStaple(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}

	// OID for id-pe-tlsfeature (1.3.6.1.5.5.7.1.24)
	tlsFeatureOID := asn1OID{1, 3, 6, 1, 5, 5, 7, 1, 24}

	for _, ext := range cert.Extensions {
		if ext.Id.Equal(tlsFeatureOID) {
			// The extension value is an ASN.1 SEQUENCE of INTEGER.
			// status_request (OCSP stapling) = 5.
			// We check if byte value 5 is present in the DER encoding.
			// The minimal valid encoding is: 30 03 02 01 05
			// (SEQUENCE { INTEGER 5 })
			for _, b := range ext.Value {
				if b == 5 {
					return true
				}
			}
		}
	}
	return false
}

// asn1OID is a local type alias to avoid importing encoding/asn1 just for
// the Equal() method on pkix.Extension.Id (which is already asn1.ObjectIdentifier).
type asn1OID = asn1.ObjectIdentifier

