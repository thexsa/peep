package probe

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// ProbeResult is the raw result from probing a target.
type ProbeResult struct {
	ConnState  *tls.ConnectionState
	Host       string
	Port       string
	IP         string
	Protocol   string   // Human-readable: "HTTPS", "SMTP/STARTTLS", "RDP", etc.
	ProbeType  string   // "direct_tls", "starttls_smtp", "rdp_x224", "starttls_ldap"
	ProbeNotes []string // Any interesting observations during probing
}

// ProbeOptions configures the probe behavior.
type ProbeOptions struct {
	Host      string
	Port      string
	Timeout   time.Duration
	Proto     string      // Force protocol: "", "tls", "smtp", "rdp", "ldap", etc.
	TLSConfig *tls.Config // Optional custom TLS configuration (e.g., for version/cipher probing)
}

// buildTLSConfig clones custom (if provided) or creates a default TLS config
// with InsecureSkipVerify enabled and ServerName populated.
func buildTLSConfig(custom *tls.Config, hostname string) *tls.Config {
	if custom != nil {
		cfg := custom.Clone()
		cfg.InsecureSkipVerify = true
		if cfg.ServerName == "" {
			cfg.ServerName = hostname
		}
		return cfg
	}
	return &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         hostname,
	}
}

// portProtocolMap maps well-known ports to their protocol strategies.
var portProtocolMap = map[string]string{
	"443":  "tls",
	"8443": "tls",
	"587":  "smtp",
	"25":   "smtp",
	"465":  "tls",  // SMTPS (implicit TLS)
	"636":  "tls",  // LDAPS (implicit TLS)
	"389":  "ldap", // LDAP STARTTLS
	"3389": "rdp",
	"993":  "tls",      // IMAPS (implicit TLS)
	"995":  "tls",      // POP3S (implicit TLS)
	"5986": "tls",      // WinRM HTTPS
	"853":  "tls",      // DNS over TLS
	"21":   "ftp",      // FTP STARTTLS (AUTH TLS)
	"990":  "tls",      // FTPS (implicit TLS)
	"110":  "pop3",     // POP3 STLS
	"143":  "imap",     // IMAP STARTTLS
	"1433": "mssql",    // Microsoft SQL Server
	"3306": "mysql",    // MySQL
	"5432": "postgres", // PostgreSQL
	"5222": "xmpp",     // XMPP STARTTLS
}

// protocolNames maps probe types to human-readable names.
var protocolNames = map[string]string{
	"tls":      "Direct TLS",
	"smtp":     "SMTP/STARTTLS",
	"rdp":      "RDP (X.224 → TLS)",
	"ldap":     "LDAP/STARTTLS",
	"ftp":      "FTP/STARTTLS (AUTH TLS)",
	"pop3":     "POP3/STLS",
	"imap":     "IMAP/STARTTLS",
	"mssql":    "MSSQL/TDS-TLS",
	"mysql":    "MySQL/SSL",
	"postgres": "PostgreSQL/SSL",
	"xmpp":     "XMPP/STARTTLS",
}

// Probe connects to the target and extracts TLS information using the
// appropriate protocol strategy. It auto-detects the protocol based on port
// unless overridden via ProbeOptions.Proto.
func Probe(opts ProbeOptions) (*ProbeResult, error) {
	// Resolve IP
	ip := resolveIP(opts.Host)

	// Determine protocol strategy
	proto := opts.Proto
	if proto == "" {
		proto = detectProtocol(opts.Port)
	}

	target := net.JoinHostPort(opts.Host, opts.Port)

	var (
		state *tls.ConnectionState
		notes []string
		err   error
	)

	switch proto {
	case "smtp":
		state, notes, err = probeSTARTTLS(target, opts.Host, opts.Timeout, opts.TLSConfig)
	case "rdp":
		state, notes, err = probeRDP(target, opts.Host, opts.Timeout, opts.TLSConfig)
	case "ldap":
		state, notes, err = probeLDAPStartTLS(target, opts.Host, opts.Timeout, opts.TLSConfig)
	case "ftp":
		state, notes, err = probeFTPStartTLS(target, opts.Host, opts.Timeout, opts.TLSConfig)
	case "pop3":
		state, notes, err = probePOP3StartTLS(target, opts.Host, opts.Timeout, opts.TLSConfig)
	case "imap":
		state, notes, err = probeIMAPStartTLS(target, opts.Host, opts.Timeout, opts.TLSConfig)
	case "mssql":
		state, notes, err = probeMSSQLTLS(target, opts.Host, opts.Timeout, opts.TLSConfig)
	case "mysql":
		state, notes, err = probeMySQLSSL(target, opts.Host, opts.Timeout, opts.TLSConfig)
	case "postgres":
		state, notes, err = probePostgresSSL(target, opts.Host, opts.Timeout, opts.TLSConfig)
	case "xmpp":
		state, notes, err = probeXMPPStartTLS(target, opts.Host, opts.Timeout, opts.TLSConfig)
	default:
		// Default: try direct TLS
		state, notes, err = probeDirectTLS(target, opts.Host, opts.Timeout, opts.TLSConfig)
	}

	if err != nil {
		return nil, fmt.Errorf("probe failed for %s (%s): %w", target, protocolNames[proto], err)
	}

	protocolName := protocolNames[proto]
	if protocolName == "" {
		protocolName = "Direct TLS"
	}

	return &ProbeResult{
		ConnState:  state,
		Host:       opts.Host,
		Port:       opts.Port,
		IP:         ip,
		Protocol:   protocolName,
		ProbeType:  proto,
		ProbeNotes: notes,
	}, nil
}

// TestHandshake performs a protocol-aware TLS handshake using opts.TLSConfig
// (without redundant DNS lookups) and returns nil if the server negotiated it.
func TestHandshake(opts ProbeOptions) error {
	proto := opts.Proto
	if proto == "" {
		proto = detectProtocol(opts.Port)
	}
	target := net.JoinHostPort(opts.Host, opts.Port)

	var err error
	switch proto {
	case "smtp":
		_, _, err = probeSTARTTLS(target, opts.Host, opts.Timeout, opts.TLSConfig)
	case "rdp":
		_, _, err = probeRDP(target, opts.Host, opts.Timeout, opts.TLSConfig)
	case "ldap":
		_, _, err = probeLDAPStartTLS(target, opts.Host, opts.Timeout, opts.TLSConfig)
	case "ftp":
		_, _, err = probeFTPStartTLS(target, opts.Host, opts.Timeout, opts.TLSConfig)
	case "pop3":
		_, _, err = probePOP3StartTLS(target, opts.Host, opts.Timeout, opts.TLSConfig)
	case "imap":
		_, _, err = probeIMAPStartTLS(target, opts.Host, opts.Timeout, opts.TLSConfig)
	case "mssql":
		_, _, err = probeMSSQLTLS(target, opts.Host, opts.Timeout, opts.TLSConfig)
	case "mysql":
		_, _, err = probeMySQLSSL(target, opts.Host, opts.Timeout, opts.TLSConfig)
	case "postgres":
		_, _, err = probePostgresSSL(target, opts.Host, opts.Timeout, opts.TLSConfig)
	case "xmpp":
		_, _, err = probeXMPPStartTLS(target, opts.Host, opts.Timeout, opts.TLSConfig)
	default:
		_, _, err = probeDirectTLS(target, opts.Host, opts.Timeout, opts.TLSConfig)
	}
	return err
}

// detectProtocol determines the appropriate protocol based on port number.
func detectProtocol(port string) string {
	if proto, ok := portProtocolMap[port]; ok {
		return proto
	}
	return "tls" // Default to direct TLS
}

// resolveIP attempts to resolve the hostname to an IP address.
func resolveIP(host string) string {
	// Check if it's already an IP
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}

	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return "Unknown"
	}
	return ips[0].String()
}

// ProtocolList returns the list of supported protocols for documentation.
func ProtocolList() map[string]string {
	return map[string]string{
		"tls":      "Direct TLS handshake (HTTPS, LDAPS, IMAPS, etc.)",
		"smtp":     "SMTP STARTTLS upgrade (ports 25, 587)",
		"rdp":      "RDP X.224 negotiation followed by TLS (port 3389)",
		"ldap":     "LDAP STARTTLS extended operation (port 389)",
		"ftp":      "FTP AUTH TLS/SSL upgrade (port 21)",
		"pop3":     "POP3 STLS upgrade (port 110)",
		"imap":     "IMAP STARTTLS upgrade (port 143)",
		"mssql":    "MSSQL TDS PreLogin TLS negotiation (port 1433)",
		"mysql":    "MySQL SSL request negotiation (port 3306)",
		"postgres": "PostgreSQL SSLRequest negotiation (port 5432)",
		"xmpp":     "XMPP STARTTLS XML stream negotiation (port 5222)",
	}
}
