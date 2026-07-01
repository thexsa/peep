package analyzer

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"

	"golang.org/x/crypto/ocsp"
)

// OCSPStapleResult holds the result of checking the stapled OCSP response.
type OCSPStapleResult struct {
	Present    bool       `json:"present"`
	Status     OCSPStatus `json:"status"`
	StatusText string     `json:"status_text"`
	ProducedAt time.Time  `json:"produced_at,omitempty"`
	ThisUpdate time.Time  `json:"this_update,omitempty"`
	NextUpdate time.Time  `json:"next_update,omitempty"`
	IsStale    bool       `json:"is_stale"`
	Error      string     `json:"error,omitempty"`
}

// CheckOCSPStaple inspects the OCSP response stapled to the TLS handshake.
// It parses the response, verifies it against the issuer, and checks freshness.
func CheckOCSPStaple(state *tls.ConnectionState, issuer *x509.Certificate) OCSPStapleResult {
	if len(state.OCSPResponse) == 0 {
		return OCSPStapleResult{
			Present:    false,
			StatusText: "No OCSP response stapled to handshake",
		}
	}

	resp, err := ocsp.ParseResponse(state.OCSPResponse, issuer)
	if err != nil {
		return OCSPStapleResult{
			Present:    true,
			Status:     OCSPError,
			StatusText: "Failed to parse stapled OCSP response",
			Error:      err.Error(),
		}
	}

	result := OCSPStapleResult{
		Present:    true,
		ProducedAt: resp.ProducedAt,
		ThisUpdate: resp.ThisUpdate,
		NextUpdate: resp.NextUpdate,
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
