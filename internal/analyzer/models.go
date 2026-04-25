package analyzer

import (
	"crypto/x509"
	"time"
)

// HealthStatus represents the overall TLS health assessment.
type HealthStatus int

const (
	// ClearSkies — everything looks great, no issues found.
	ClearSkies HealthStatus = iota
	// Cloudy — not broken, but there are concerns (weak config, expiring soon, etc.).
	Cloudy
	// Stormy — critical issues: expired certs, broken chains, dangerous ciphers.
	Stormy
)

// String returns the emoji + label for a health status.
func (h HealthStatus) String() string {
	switch h {
	case ClearSkies:
		return "✅ Clear Skies"
	case Cloudy:
		return "⚠️  Cloudy"
	case Stormy:
		return "❌ Stormy"
	default:
		return "❓ Unknown"
	}
}

// Personality controls the tone of output messages.
type Personality int

const (
	// Normal — sarcastic but helpful.
	Normal Personality = iota
	// Rude — gloves off, brutally honest.
	Rude
)

// Warning represents a single diagnostic finding.
type Warning struct {
	Code     string       // Machine-readable code, e.g. "TLS_OLD_VERSION"
	Severity HealthStatus // How bad is it?
	Title    string       // Short human title: "Ancient TLS Version"
	Detail   string       // Technical detail string
	WhyNormal string      // --why explanation (normal personality)
	WhyRude   string      // --why explanation (rude personality)
}

// Why returns the appropriate explanation based on personality.
func (w Warning) Why(p Personality) string {
	if p == Rude {
		return w.WhyRude
	}
	return w.WhyNormal
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

// String returns the emoji + label for a cert role.
func (r CertRole) String() string {
	switch r {
	case RoleLeaf:
		return "📄 Leaf"
	case RoleIntermediate:
		return "📋 Intermediate (Issuing CA)"
	case RoleRoot:
		return "🏛️  Root CA"
	default:
		return "❓ Unknown"
	}
}

// RoleExplanation returns a plain-English explanation of what this role means.
func (r CertRole) RoleExplanation() string {
	switch r {
	case RoleLeaf:
		return "This is the cert that proves the server's identity. It's the one that matches " +
			"the hostname you typed. It can NOT sign other certs."
	case RoleIntermediate:
		return "This cert signed the leaf cert. Think of it as a notary — it vouches for the leaf. " +
			"The server MUST send this, or browsers won't trust the leaf. " +
			"This is usually the cert you need when someone says 'install the CA cert.'"
	case RoleRoot:
		return "The ultimate authority. This lives in your OS/browser trust store. " +
			"Servers usually should NOT send this — your computer already has it. " +
			"If you see it in the chain, it's unnecessary baggage."
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
	HasUnnecessaryRoot     bool
	ChainOrderCorrect     bool
	TrustStoreVerified    bool
	VerificationError      string
	OverallGrade          HealthStatus
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
