package analyzer

import (
	"crypto/tls"
	"fmt"
	"sort"
	"time"

	"github.com/thexsa/peep/internal/probe"
)

// CipherEnumResult holds the results of cipher suite enumeration.
type CipherEnumResult struct {
	SupportedSuites []CipherSuiteInfo   `json:"supported_suites,omitempty"`
	TLSVersions     []TLSVersionSupport `json:"tls_versions,omitempty"`
	Error           string              `json:"error,omitempty"`
}

// CipherSuiteInfo describes a single supported cipher suite.
type CipherSuiteInfo struct {
	ID      uint16       `json:"id"`
	Name    string       `json:"name"`
	Version string       `json:"version"`
	Secure  bool         `json:"secure"`
	Grade   HealthStatus `json:"grade"`
}

// TLSVersionSupport describes whether a specific TLS version is supported.
type TLSVersionSupport struct {
	Version   string       `json:"version"`
	VersionID uint16       `json:"version_id"`
	Supported bool         `json:"supported"`
	Grade     HealthStatus `json:"grade"`
}

// EnumerateCiphers probes the target using automatic port-based protocol detection
// to determine which TLS versions and cipher suites are supported.
func EnumerateCiphers(host, port string, timeout time.Duration) CipherEnumResult {
	return EnumerateCiphersWithProto(host, port, "", timeout)
}

// EnumerateCiphersWithProto probes the target using the given protocol strategy
// (Direct TLS, STARTTLS for SMTP/LDAP/FTP/IMAP/POP3/XMPP, X.224 for RDP, native SSL
// negotiation for PostgreSQL/MySQL/MSSQL) to determine supported TLS versions and ciphers.
func EnumerateCiphersWithProto(host, port, proto string, timeout time.Duration) CipherEnumResult {
	result := CipherEnumResult{}

	// Test each TLS version
	versions := []struct {
		id   uint16
		name string
	}{
		{tls.VersionSSL30, "SSLv3"},
		{tls.VersionTLS10, "TLSv1.0"},
		{tls.VersionTLS11, "TLSv1.1"},
		{tls.VersionTLS12, "TLSv1.2"},
		{tls.VersionTLS13, "TLSv1.3"},
	}

	for _, v := range versions {
		supported := testTLSVersion(host, port, proto, v.id, timeout)
		grade := gradeTLSVersion(v.id)
		result.TLSVersions = append(result.TLSVersions, TLSVersionSupport{
			Version:   v.name,
			VersionID: v.id,
			Supported: supported,
			Grade:     grade,
		})
	}

	// Enumerate cipher suites for TLS 1.2 (TLS 1.3 has fixed suites)
	result.SupportedSuites = enumerateTLS12Ciphers(host, port, proto, timeout)

	// Add TLS 1.3 suites if supported
	for _, v := range result.TLSVersions {
		if v.VersionID == tls.VersionTLS13 && v.Supported {
			tls13Suites := getTLS13Suites()
			result.SupportedSuites = append(result.SupportedSuites, tls13Suites...)
			break
		}
	}

	// Sort by grade (worst first for visibility)
	sort.Slice(result.SupportedSuites, func(i, j int) bool {
		if result.SupportedSuites[i].Grade != result.SupportedSuites[j].Grade {
			return result.SupportedSuites[i].Grade > result.SupportedSuites[j].Grade
		}
		return result.SupportedSuites[i].Name < result.SupportedSuites[j].Name
	})

	return result
}

// testTLSVersion attempts a protocol-aware connection with a specific TLS version.
func testTLSVersion(host, port, proto string, version uint16, timeout time.Duration) bool {
	conf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
		MinVersion:         version,
		MaxVersion:         version,
	}

	err := probe.TestHandshake(probe.ProbeOptions{
		Host:      host,
		Port:      port,
		Timeout:   timeout,
		Proto:     proto,
		TLSConfig: conf,
	})
	return err == nil
}

// enumerateTLS12Ciphers tests each TLS 1.2 cipher suite to see which ones
// the server supports.
func enumerateTLS12Ciphers(host, port, proto string, timeout time.Duration) []CipherSuiteInfo {
	var supported []CipherSuiteInfo

	// Test secure cipher suites
	for _, suite := range tls.CipherSuites() {
		if testCipherSuite(host, port, proto, suite.ID, timeout) {
			supported = append(supported, CipherSuiteInfo{
				ID:      suite.ID,
				Name:    suite.Name,
				Version: formatSuiteVersions(suite.SupportedVersions),
				Secure:  true,
				Grade:   MainCharacterEnergy,
			})
		}
	}

	// Test insecure cipher suites
	for _, suite := range tls.InsecureCipherSuites() {
		if testCipherSuite(host, port, proto, suite.ID, timeout) {
			supported = append(supported, CipherSuiteInfo{
				ID:      suite.ID,
				Name:    suite.Name,
				Version: formatSuiteVersions(suite.SupportedVersions),
				Secure:  false,
				Grade:   WrittenInCrayon,
			})
		}
	}

	return supported
}

// testCipherSuite attempts a protocol-aware connection with a specific cipher suite.
func testCipherSuite(host, port, proto string, suiteID uint16, timeout time.Duration) bool {
	conf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
		CipherSuites:       []uint16{suiteID},
	}

	err := probe.TestHandshake(probe.ProbeOptions{
		Host:      host,
		Port:      port,
		Timeout:   timeout,
		Proto:     proto,
		TLSConfig: conf,
	})
	return err == nil
}

// getTLS13Suites returns the TLS 1.3 cipher suites (they're all secure).
// TLS 1.3 suites can't be configured in Go — they're always available.
func getTLS13Suites() []CipherSuiteInfo {
	return []CipherSuiteInfo{
		{Name: "TLS_AES_128_GCM_SHA256", Version: "TLSv1.3", Secure: true, Grade: MainCharacterEnergy},
		{Name: "TLS_AES_256_GCM_SHA384", Version: "TLSv1.3", Secure: true, Grade: MainCharacterEnergy},
		{Name: "TLS_CHACHA20_POLY1305_SHA256", Version: "TLSv1.3", Secure: true, Grade: MainCharacterEnergy},
	}
}

func formatSuiteVersions(versions []uint16) string {
	var names []string
	for _, v := range versions {
		names = append(names, getTLSVersionName(v))
	}
	if len(names) == 0 {
		return "Unknown"
	}
	result := names[0]
	if len(names) > 1 {
		result = fmt.Sprintf("%s–%s", names[0], names[len(names)-1])
	}
	return result
}
