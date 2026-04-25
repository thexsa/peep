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

// Warning represents a single diagnostic finding.
type Warning struct {
	Code     string       // Machine-readable code, e.g. "TLS_OLD_VERSION"
	Severity HealthStatus // How bad is it?
	Title    string       // Short human title: "Ancient TLS Version"
	Detail   string       // Technical detail string
	Why      string       // Sarcastic commentary
	Explain  string       // --explain: detailed explanation of why this matters
	Fix      string       // --explain: recommended fix
	DocRef   string       // --explain: peep docs command for more info
}

// TargetInfo holds information about the connection target.
type TargetInfo struct {
	Host       string
	Port       string
	IP         string
	Protocol   string // "HTTPS", "SMTP/STARTTLS", "RDP", "LDAPS", etc.
	ProbeType  string // "direct_tls", "starttls_smtp", "rdp_x224", "starttls_ldap"
}

// HandshakeAnalysis holds the TLS handshake assessment.
type HandshakeAnalysis struct {
	TLSVersion      string       // "TLSv1.3", "TLSv1.2", etc.
	TLSVersionRaw   uint16       // Raw TLS version constant
	CipherSuite     string       // Human-readable cipher suite name
	CipherSuiteRaw  uint16       // Raw cipher suite constant
	CipherGrade     HealthStatus // Assessment of the cipher
	VersionGrade    HealthStatus // Assessment of the TLS version
	OverallGrade    HealthStatus
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
	Depth            int
	Role             CertRole
	Subject          string
	Issuer           string
	CommonName       string
	Organization     string
	DNSNames         []string
	IPAddresses      []string
	NotBefore        time.Time
	NotAfter         time.Time
	DaysRemaining    int
	IsExpired        bool
	ExpiryGrade      HealthStatus
	SerialNumber     string
	SignatureAlg     string
	SignatureGrade   HealthStatus
	KeyType          string // "RSA 2048", "ECDSA P-256", etc.
	KeyBits          int
	KeyGrade         HealthStatus
	Fingerprint      string // SHA-256 hex
	IsSelfSigned     bool
	IsWildcard       bool
	IsCA             bool
	HostnameMatch    bool   // Does the cert cover the target hostname?
	OverallGrade     HealthStatus
	RawCert          *x509.Certificate
}

// ChainAnalysis holds the assessment of the entire certificate chain.
type ChainAnalysis struct {
	Certificates       []CertAnalysis
	ChainLength        int
	HasMissingIntermediate bool
	HasUnnecessaryRoot          bool
	LeafOnlyMissingIntermediate bool // Leaf only, and issuer is NOT a root CA
	ChainOrderCorrect          bool
	TrustStoreVerified         bool
	VerificationError           string
	OverallGrade               HealthStatus
}

// DiagnosticReport is the complete output of a peep scan.
type DiagnosticReport struct {
	Target       TargetInfo
	Handshake    HandshakeAnalysis
	Chain        ChainAnalysis
	Warnings     []Warning
	OverallStatus HealthStatus
	ScanDuration time.Duration
	Timestamp    time.Time
}
