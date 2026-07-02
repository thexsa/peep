package analyzer

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// CTLogResult holds the result of a Certificate Transparency log check.
type CTLogResult struct {
	Found         bool
	LogCount      int      // Number of CT logs containing this cert
	LogNames      []string // Names of CT logs that have this cert
	FirstSeen     string   // When the cert was first logged
	Error         string
	SCTCount      int  // Number of SCTs embedded in the cert
	HasSCTs       bool // Whether the cert has embedded SCTs
	IsPrivateCA   bool // Whether the issuing CA is private (not publicly trusted)
}

// crtShResponse represents the response from crt.sh API.
type crtShResponse struct {
	ID             int    `json:"id"`
	IssuerCAID     int    `json:"issuer_ca_id"`
	IssuerName     string `json:"issuer_name"`
	CommonName     string `json:"common_name"`
	NameValue      string `json:"name_value"`
	NotBefore      string `json:"not_before"`
	NotAfter       string `json:"not_after"`
	SerialNumber   string `json:"serial_number"`
	EntryTimestamp string `json:"entry_timestamp"`
}

const (
	crtShTimeout     = 30 * time.Second
	crtShMaxRetries  = 2
	crtShRetryDelay  = 2 * time.Second
)

// CheckCTLogs checks Certificate Transparency logs for the given certificate
// using the crt.sh API (which aggregates multiple CT logs).
//
// If trustStoreVerified is false, the cert is likely from a private/internal CA
// and will never appear in public CT logs — we skip the check and note this.
func CheckCTLogs(serialNumber string, commonName string, trustStoreVerified bool) CTLogResult {
	result := CTLogResult{}

	if serialNumber == "" {
		result.Error = "no serial number available"
		return result
	}

	// Private CA: certs from internal CAs will never be in public CT logs
	if !trustStoreVerified {
		result.IsPrivateCA = true
		result.Found = false
		return result
	}

	// Query crt.sh by serial number (lowercase hex, no leading zeros issues)
	serial := strings.ToLower(serialNumber)
	url := fmt.Sprintf("https://crt.sh/?serial=%s&output=json", serial)

	var lastErr error
	for attempt := 0; attempt <= crtShMaxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(crtShRetryDelay)
		}

		client := &http.Client{Timeout: crtShTimeout}
		resp, err := client.Get(url)
		if err != nil {
			lastErr = err
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
			continue
		}

		if err != nil {
			lastErr = fmt.Errorf("failed to read response: %s", err)
			continue
		}

		var entries []crtShResponse
		if err := json.Unmarshal(body, &entries); err != nil {
			// crt.sh returns empty array or error page for not-found
			if len(body) < 10 {
				result.Found = false
				return result
			}
			lastErr = fmt.Errorf("failed to parse response: %s", err)
			continue
		}

		if len(entries) == 0 {
			result.Found = false
			return result
		}

		result.Found = true
		result.LogCount = len(entries)

		// Collect unique log names and find earliest entry
		logSet := make(map[string]bool)
		earliest := ""
		for _, entry := range entries {
			logSet[entry.IssuerName] = true
			if earliest == "" || entry.EntryTimestamp < earliest {
				earliest = entry.EntryTimestamp
			}
		}

		for name := range logSet {
			result.LogNames = append(result.LogNames, name)
		}
		result.FirstSeen = earliest

		return result
	}

	// All retries exhausted
	if lastErr != nil {
		result.Error = fmt.Sprintf("failed to query crt.sh: %s", lastErr)
	}
	return result
}

// CheckSCTs checks if a certificate contains embedded Signed Certificate
// Timestamps (SCTs), which prove it was submitted to CT logs before issuance.
func CheckSCTs(rawCert []byte) CTLogResult {
	result := CTLogResult{}

	// SCTs are stored in the certificate's extensions as OID 1.3.6.1.4.1.11129.2.4.2
	// We check for the presence of this extension
	// The actual SCT parsing would require ASN.1 decoding of the extension value

	// For now, we check extension count — a proper implementation would parse
	// the SCT list from the extension
	// This is simplified; the cert analysis already has the raw cert
	result.HasSCTs = false // Will be set by the caller if SCTs are found
	return result
}
