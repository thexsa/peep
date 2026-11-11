package cli

import (
	"net"
	"strings"
)

// parseTarget extracts a clean host and port (defaulting to "443") from a user
// target string. Supports hostnames, IPv4, bracketed IPv6 ([2001:db8::1]:8443 or
// [2001:db8::1]), bare IPv6 (2001:db8::1 or ::1), and http(s):// URLs.
func parseTarget(target string) (string, string) {
	target = strings.TrimSpace(target)
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	if idx := strings.IndexByte(target, '/'); idx != -1 {
		target = target[:idx]
	}

	// Bracketed IPv6 without port: [2001:db8::1] or [::1]
	if strings.HasPrefix(target, "[") && strings.HasSuffix(target, "]") {
		inner := target[1 : len(target)-1]
		if inner != "" {
			return inner, "443"
		}
	}

	// Bare IPv4 or bare IPv6 without port (e.g., 2001:db8::1, ::1, 192.0.2.1)
	if ip := net.ParseIP(target); ip != nil {
		return target, "443"
	}

	host, port, err := net.SplitHostPort(target)
	if err != nil || port == "" {
		return target, "443"
	}
	return host, port
}

// parseHostOnly extracts just the host portion (stripping any scheme, path,
// brackets, or port) for multi-port scanners like portscan and find-certs.
func parseHostOnly(target string) string {
	host, _ := parseTarget(target)
	return host
}

// isTransientSocketError reports whether err indicates temporary socket/FD
// exhaustion (EMFILE, ENFILE, WSAENOBUFS, ephemeral port exhaustion) that
// warrants a brief retry rather than treating the port as closed.
func isTransientSocketError(err error) bool {
	if err == nil {
		return false
	}
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "too many open files") ||
		strings.Contains(lower, "no buffer space available") ||
		strings.Contains(lower, "only one usage of each socket address") ||
		strings.Contains(lower, "cannot assign requested address")
}
