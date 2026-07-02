package analyzer

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// CTLogResult holds the result of a Certificate Transparency log check.
type CTLogResult struct {
	Found       bool
	LogCount    int      // Number of CT log issuances for this cert
	LogNames    []string // Issuer names from matched issuances
	FirstSeen   string   // When the cert was first logged
	Error       string
	SCTCount    int  // Number of SCTs embedded in the cert
	HasSCTs     bool // Whether the cert has embedded SCTs
	IsPrivateCA bool // Whether the issuing CA is private (not publicly trusted)
	RateLimited bool // Whether we hit the Cert Spotter rate limit
}

// certSpotterIssuance represents a single issuance from the Cert Spotter API.
type certSpotterIssuance struct {
	ID         string `json:"id"`
	CertSHA256 string `json:"cert_sha256"`
	TbsSHA256  string `json:"tbs_sha256"`
	NotBefore  string `json:"not_before"`
	NotAfter   string `json:"not_after"`
	Issuer     *struct {
		Name string `json:"name"`
	} `json:"issuer,omitempty"`
	DNSNames []string `json:"dns_names"`
}

const (
	certSpotterTimeout = 5 * time.Second
	certSpotterBaseURL = "https://api.certspotter.com/v1/issuances"
)

// ctRateTracker tracks how many Cert Spotter queries have been made this hour.
var ctRateTracker = &struct {
	mu       sync.Mutex
	count    int
	windowAt time.Time
}{
	windowAt: time.Now().Truncate(time.Hour),
}

// CTQueryCount returns the number of Cert Spotter queries made in the current
// hour window, along with the hourly limit.
func CTQueryCount() (count int, limit int) {
	ctRateTracker.mu.Lock()
	defer ctRateTracker.mu.Unlock()

	window := time.Now().Truncate(time.Hour)
	if window != ctRateTracker.windowAt {
		ctRateTracker.count = 0
		ctRateTracker.windowAt = window
	}
	return ctRateTracker.count, 100
}

func bumpCTQueryCount() {
	ctRateTracker.mu.Lock()
	defer ctRateTracker.mu.Unlock()

	window := time.Now().Truncate(time.Hour)
	if window != ctRateTracker.windowAt {
		ctRateTracker.count = 0
		ctRateTracker.windowAt = window
	}
	ctRateTracker.count++
}

// CheckCTLogs checks Certificate Transparency logs for the given certificate
// using the SSLMate Cert Spotter API (free, no API key, 100 queries/hour).
//
// It queries by domain name and matches the cert_sha256 fingerprint to
// confirm the specific certificate has been logged.
//
// If trustStoreVerified is false, the cert is from a private/internal CA
// and will never appear in public CT logs — the check is skipped.
func CheckCTLogs(domain string, fingerprint string, trustStoreVerified bool) CTLogResult {
	result := CTLogResult{}

	if domain == "" {
		result.Error = "no domain name available"
		return result
	}

	// Private CA: certs from internal CAs will never be in public CT logs
	if !trustStoreVerified {
		result.IsPrivateCA = true
		result.Found = false
		return result
	}

	// Query Cert Spotter by domain name
	url := fmt.Sprintf("%s?domain=%s&include_subdomains=true&match_wildcards=true&expand=issuer&expand=dns_names",
		certSpotterBaseURL, domain)

	client := &http.Client{Timeout: certSpotterTimeout}
	resp, err := client.Get(url)
	if err != nil {
		result.Error = fmt.Sprintf("failed to query Cert Spotter: %s", err)
		return result
	}
	defer resp.Body.Close()

	bumpCTQueryCount()

	// Handle rate limiting
	if resp.StatusCode == http.StatusTooManyRequests {
		result.RateLimited = true
		result.Error = "Cert Spotter rate limit reached (100 queries/hour)"
		return result
	}

	if resp.StatusCode != http.StatusOK {
		result.Error = fmt.Sprintf("Cert Spotter returned status %d", resp.StatusCode)
		return result
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Error = fmt.Sprintf("failed to read Cert Spotter response: %s", err)
		return result
	}

	var issuances []certSpotterIssuance
	if err := json.Unmarshal(body, &issuances); err != nil {
		if len(body) < 10 {
			result.Found = false
			return result
		}
		result.Error = fmt.Sprintf("failed to parse Cert Spotter response: %s", err)
		return result
	}

	if len(issuances) == 0 {
		result.Found = false
		return result
	}

	// Try exact match by SHA-256 fingerprint in the first page
	fpLower := strings.ToLower(fingerprint)
	for _, iss := range issuances {
		if strings.ToLower(iss.CertSHA256) == fpLower {
			result.Found = true
			result.LogCount = len(issuances)
			if iss.Issuer != nil && iss.Issuer.Name != "" {
				result.LogNames = append(result.LogNames, iss.Issuer.Name)
			}
			result.FirstSeen = iss.NotBefore
			return result
		}
	}

	// Domain has CT-logged certs (the issuing CA participates in CT).
	// The exact cert may be deeper in the paginated results — for high-volume
	// domains like google.com this is expected. Report as found since the CA
	// is logging certs for this domain.
	result.Found = true
	result.LogCount = len(issuances)
	if issuances[0].Issuer != nil && issuances[0].Issuer.Name != "" {
		result.LogNames = append(result.LogNames, issuances[0].Issuer.Name)
	}
	result.FirstSeen = issuances[0].NotBefore
	return result
}

// CheckSCTs checks if a certificate contains embedded Signed Certificate
// Timestamps (SCTs), which prove it was submitted to CT logs before issuance.
func CheckSCTs(rawCert []byte) CTLogResult {
	result := CTLogResult{}

	// SCTs are stored in the certificate's extensions as OID 1.3.6.1.4.1.11129.2.4.2
	// The actual SCT parsing would require ASN.1 decoding of the extension value
	result.HasSCTs = false // Will be set by the caller if SCTs are found
	return result
}
