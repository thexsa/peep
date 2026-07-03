package analyzer

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

// OCSPResult holds the result of an OCSP check.
type OCSPResult struct {
	Status       OCSPStatus `json:"status"`
	StatusText   string     `json:"status_text"`
	ProducedAt   time.Time  `json:"produced_at,omitempty"`
	ThisUpdate   time.Time  `json:"this_update,omitempty"`
	NextUpdate   time.Time  `json:"next_update,omitempty"`
	RevokedAt    time.Time  `json:"revoked_at,omitempty"`
	RevokeReason string     `json:"revoke_reason,omitempty"`
	ResponderURL string     `json:"responder_url,omitempty"`
	Error        string     `json:"error,omitempty"`
}

// OCSPStatus represents the OCSP response status.
type OCSPStatus int

const (
	OCSPGood    OCSPStatus = iota
	OCSPRevoked
	OCSPUnknown
	OCSPError
)

// CheckOCSP performs an OCSP check for the given certificate.
// It requires the issuer certificate to construct the request.
func CheckOCSP(cert *x509.Certificate, issuer *x509.Certificate, timeout time.Duration) OCSPResult {
	if len(cert.OCSPServer) == 0 {
		return OCSPResult{
			Status:     OCSPUnknown,
			StatusText: "No OCSP responder URL in certificate",
			Error:      "certificate does not contain an OCSP responder URL",
		}
	}

	ocspURL := cert.OCSPServer[0]

	// Create OCSP request
	ocspReq, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return OCSPResult{
			Status:       OCSPError,
			StatusText:   "Failed to create OCSP request",
			ResponderURL: ocspURL,
			Error:        err.Error(),
		}
	}

	// Send OCSP request via HTTP GET (base64-encoded in URL)
	// Fall back to POST if the URL would be too long
	var resp *http.Response
	client := &http.Client{Timeout: timeout}

	encodedReq := base64.StdEncoding.EncodeToString(ocspReq)
	getURL := fmt.Sprintf("%s/%s", ocspURL, encodedReq)

	if len(getURL) < 255 {
		resp, err = client.Get(getURL)
	} else {
		// Use POST for large requests
		resp, err = client.Post(ocspURL, "application/ocsp-request",
			bytes.NewReader(ocspReq))
	}

	if err != nil {
		// Try POST as fallback
		resp, err = client.Post(ocspURL, "application/ocsp-request",
			bytes.NewReader(ocspReq))
		if err != nil {
			return OCSPResult{
				Status:       OCSPError,
				StatusText:   "Failed to contact OCSP responder",
				ResponderURL: ocspURL,
				Error:        err.Error(),
			}
		}
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return OCSPResult{
			Status:       OCSPError,
			StatusText:   "Failed to read OCSP response",
			ResponderURL: ocspURL,
			Error:        err.Error(),
		}
	}

	// Parse OCSP response
	ocspResp, err := ocsp.ParseResponse(respBytes, issuer)
	if err != nil {
		return OCSPResult{
			Status:       OCSPError,
			StatusText:   "Failed to parse OCSP response",
			ResponderURL: ocspURL,
			Error:        err.Error(),
		}
	}

	result := OCSPResult{
		ResponderURL: ocspURL,
		ProducedAt:   ocspResp.ProducedAt,
		ThisUpdate:   ocspResp.ThisUpdate,
		NextUpdate:   ocspResp.NextUpdate,
	}

	switch ocspResp.Status {
	case ocsp.Good:
		result.Status = OCSPGood
		result.StatusText = "Good — certificate is valid and not revoked"
	case ocsp.Revoked:
		result.Status = OCSPRevoked
		result.StatusText = "REVOKED — certificate has been revoked!"
		result.RevokedAt = ocspResp.RevokedAt
		result.RevokeReason = revokeReasonText(ocspResp.RevocationReason)
	case ocsp.Unknown:
		result.Status = OCSPUnknown
		result.StatusText = "Unknown — OCSP responder doesn't know about this cert"
	default:
		result.Status = OCSPError
		result.StatusText = fmt.Sprintf("Unexpected OCSP status: %d", ocspResp.Status)
	}

	return result
}

func revokeReasonText(reason int) string {
	reasons := map[int]string{
		0: "Unspecified",
		1: "Key Compromise",
		2: "CA Compromise",
		3: "Affiliation Changed",
		4: "Superseded",
		5: "Cessation of Operation",
		6: "Certificate Hold",
		8: "Remove from CRL",
		9: "Privilege Withdrawn",
		10: "AA Compromise",
	}
	if text, ok := reasons[reason]; ok {
		return text
	}
	return fmt.Sprintf("Unknown reason (%d)", reason)
}
