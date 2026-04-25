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
	Protocol   string // Human-readable: "HTTPS", "SMTP/STARTTLS", "RDP", etc.
	ProbeType  string // "direct_tls", "starttls_smtp", "rdp_x224", "starttls_ldap"
	ProbeNotes []string // Any interesting observations during probing
}

// ProbeOptions configures the probe behavior.
type ProbeOptions struct {
	Host     string
	Port     string
	Timeout  time.Duration
	Proto    string // Force protocol: "", "tls", "smtp", "rdp", "ldap"
}

// portProtocolMap maps well-known ports to their protocol strategies.
var portProtocolMap = map[string]string{
	"443":  "tls",
	"8443": "tls",
	"587":  "smtp",
	"25":   "smtp",
	"465":  "tls",   // SMTPS (implicit TLS)
	"636":  "tls",   // LDAPS (implicit TLS)
	"389":  "ldap",  // LDAP STARTTLS
	"3389": "rdp",
	"993":  "tls",   // IMAPS
	"995":  "tls",   // POP3S
	"5986": "tls",   // WinRM HTTPS
	"853":  "tls",   // DNS over TLS
}

// protocolNames maps probe types to human-readable names.
var protocolNames = map[string]string{
	"tls":  "Direct TLS",
	"smtp": "SMTP/STARTTLS",
	"rdp":  "RDP (X.224 → TLS)",
	"ldap": "LDAP/STARTTLS",
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
		state, notes, err = probeSTARTTLS(target, opts.Host, opts.Timeout)
	case "rdp":
		state, notes, err = probeRDP(target, opts.Host, opts.Timeout)
	case "ldap":
		state, notes, err = probeLDAPStartTLS(target, opts.Host, opts.Timeout)
	default:
		// Default: try direct TLS
		state, notes, err = probeDirectTLS(target, opts.Host, opts.Timeout)
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
		"tls":  "Direct TLS handshake (HTTPS, LDAPS, IMAPS, etc.)",
		"smtp": "SMTP STARTTLS upgrade (ports 25, 587)",
		"rdp":  "RDP X.224 negotiation followed by TLS (port 3389)",
		"ldap": "LDAP STARTTLS extended operation (port 389)",
	}
}
