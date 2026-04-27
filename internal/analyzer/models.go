package analyzer

import (
	"crypto/x509"
	"time"
)

// HealthStatus represents the overall TLS health assessment.
type HealthStatus int

const (
	// MainCharacterEnergy — everything looks great, no issues found.
	MainCharacterEnergy HealthStatus = iota
	// MallCopCredentials — not broken, but there are concerns (weak config, expiring soon, etc.).
	MallCopCredentials
	// WrittenInCrayon — critical issues: expired certs, broken chains, dangerous ciphers.
	WrittenInCrayon
)

// String returns the label for a health status.
func (h HealthStatus) String() string {
	switch h {
	case MainCharacterEnergy:
		return "Main Character Energy"
	case MallCopCredentials:
		return "Mall Cop Credentials"
	case WrittenInCrayon:
		return "Appears to be Written in Crayon"
	default:
		return "Unknown"
	}
}

// MarshalJSON outputs the health status as a JSON string.
func (h HealthStatus) MarshalJSON() ([]byte, error) {
	var s string
	switch h {
	case MainCharacterEnergy:
		s = "pass"
	case MallCopCredentials:
		s = "warn"
	case WrittenInCrayon:
		s = "fail"
	default:
		s = "unknown"
	}
	return []byte(`"` + s + `"`), nil
}

// Warning represents a single diagnostic finding.
type Warning struct {
	Code     string       `json:"code"`
	Severity HealthStatus `json:"severity"`
	Title    string       `json:"title"`
	Detail   string       `json:"detail"`
	Why      string       `json:"-"`
	Explain  string       `json:"explain,omitempty"`
	Fix      string       `json:"fix,omitempty"`
	DocRef   string       `json:"doc_ref,omitempty"`
}

// TargetInfo holds information about the connection target.
type TargetInfo struct {
	Host       string `json:"host"`
	Port       string `json:"port"`
	IP         string `json:"ip"`
	Protocol   string `json:"protocol"`
	ProbeType  string `json:"probe_type"`
}

// HandshakeAnalysis holds the TLS handshake assessment.
type HandshakeAnalysis struct {
	TLSVersion      string       `json:"tls_version"`
	TLSVersionRaw   uint16       `json:"tls_version_raw"`
	CipherSuite     string       `json:"cipher_suite"`
	CipherSuiteRaw  uint16       `json:"cipher_suite_raw"`
	CipherGrade     HealthStatus `json:"cipher_grade"`
	VersionGrade    HealthStatus `json:"version_grade"`
	OverallGrade    HealthStatus `json:"overall_grade"`
}

// CertRole identifies a certificate's position in the chain.
type CertRole int

const (
	RoleLeaf         CertRole = iota
	RoleIntermediate
	RoleRoot
)

// String returns the label for a cert role.
func (r CertRole) String() string {
	switch r {
	case RoleLeaf:
		return "Leaf"
	case RoleIntermediate:
		return "Issuing CA"
	case RoleRoot:
		return "Root CA"
	default:
		return "Unknown"
	}
}

// MarshalJSON outputs the cert role as a JSON string.
func (r CertRole) MarshalJSON() ([]byte, error) {
	var s string
	switch r {
	case RoleLeaf:
		s = "leaf"
	case RoleIntermediate:
		s = "intermediate"
	case RoleRoot:
		s = "root"
	default:
		s = "unknown"
	}
	return []byte(`"` + s + `"`), nil
}

// RoleExplanation returns a plain-English explanation of what this role means.
func (r CertRole) RoleExplanation() string {
	switch r {
	case RoleLeaf:
		return "This is the server's identity cert — the one that proves \"I am who I say I am.\" " +
			"It matches the hostname you typed and cannot sign other certs."
	case RoleIntermediate:
		return "The notary. This cert vouches for the leaf. " +
			"The server MUST send this or browsers will throw a tantrum. " +
			"When someone says 'install the CA cert,' this is usually what they mean."
	case RoleRoot:
		return "The boss. Lives in your OS/browser trust store. " +
			"The server shouldn't send this — your machine already has it. " +
			"If it's in the chain, it's dead weight."
	default:
		return ""
	}
}

// CertAnalysis holds the assessment of a single certificate.
type CertAnalysis struct {
	Depth            int          `json:"depth"`
	Role             CertRole     `json:"role"`
	Subject          string       `json:"subject"`
	Issuer           string       `json:"issuer"`
	CommonName       string       `json:"common_name"`
	Organization     string       `json:"organization,omitempty"`
	DNSNames         []string     `json:"dns_names,omitempty"`
	IPAddresses      []string     `json:"ip_addresses,omitempty"`
	NotBefore        time.Time    `json:"not_before"`
	NotAfter         time.Time    `json:"not_after"`
	DaysRemaining    int          `json:"days_remaining"`
	IsExpired        bool         `json:"is_expired"`
	ExpiryGrade      HealthStatus `json:"expiry_grade"`
	SerialNumber     string       `json:"serial_number"`
	SignatureAlg     string       `json:"signature_algorithm"`
	SignatureGrade   HealthStatus `json:"signature_grade"`
	KeyType          string       `json:"key_type"`
	KeyBits          int          `json:"key_bits"`
	KeyGrade         HealthStatus `json:"key_grade"`
	Fingerprint      string       `json:"fingerprint_sha256"`
	IsSelfSigned     bool         `json:"is_self_signed"`
	IsWildcard       bool         `json:"is_wildcard"`
	IsCA             bool         `json:"is_ca"`
	HostnameMatch    bool         `json:"hostname_match"`
	OverallGrade     HealthStatus `json:"overall_grade"`
	RawCert          *x509.Certificate `json:"-"`
}

// ChainAnalysis holds the assessment of the entire certificate chain.
type ChainAnalysis struct {
	Certificates                []CertAnalysis `json:"certificates"`
	ChainLength                 int            `json:"chain_length"`
	HasMissingIntermediate      bool           `json:"has_missing_intermediate"`
	HasWrongIntermediate        bool           `json:"has_wrong_intermediate"`
	HasUnnecessaryRoot          bool           `json:"has_unnecessary_root"`
	LeafOnlyMissingIntermediate bool           `json:"leaf_only_missing_intermediate"`
	NoIssuingCAInResponse       bool           `json:"no_issuing_ca_in_response"`
	ChainOrderCorrect           bool           `json:"chain_order_correct"`
	TrustStoreVerified          bool           `json:"trust_store_verified"`
	VerificationError           string         `json:"verification_error,omitempty"`
	OverallGrade                HealthStatus   `json:"overall_grade"`
}

// DiagnosticReport is the complete output of a peep scan.
type DiagnosticReport struct {
	Target       TargetInfo        `json:"target"`
	Handshake    HandshakeAnalysis `json:"handshake"`
	Chain        ChainAnalysis     `json:"chain"`
	Warnings     []Warning         `json:"warnings"`
	OverallStatus HealthStatus     `json:"overall_status"`
	ScanDuration time.Duration     `json:"scan_duration_ms"`
	Timestamp    time.Time         `json:"timestamp"`
}
