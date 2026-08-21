package analyzer

import (
	"os"
	"runtime"
)

// GetSystemCAStorePath returns the filesystem path to the system's CA certificate
// trust store, or a descriptive string for OS-managed stores (macOS Keychain, Windows CertStore).
// It respects SSL_CERT_FILE and SSL_CERT_DIR environment variables (same as Go's crypto/x509).
func GetSystemCAStorePath() string {
	if f := os.Getenv("SSL_CERT_FILE"); f != "" {
		if _, err := os.Stat(f); err == nil {
			return f
		}
	}
	if d := os.Getenv("SSL_CERT_DIR"); d != "" {
		if _, err := os.Stat(d); err == nil {
			return d
		}
	}

	switch runtime.GOOS {
	case "darwin":
		return "/System/Library/Keychains/SystemRootCertificates.keychain"
	case "windows":
		return "Windows Certificate Store (Cert:\\LocalMachine\\Root)"
	case "aix":
		paths := []string{
			"/var/ssl/certs/ca-bundle.crt",
			"/opt/freeware/etc/ssl/certs/ca-bundle.crt",
			"/etc/ssl/certs",
		}
		for _, p := range paths {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
		return "/var/ssl/certs/"
	default:
		paths := []string{
			"/etc/ssl/certs/ca-certificates.crt",
			"/etc/pki/tls/certs/ca-bundle.crt",
			"/etc/ssl/ca-bundle.pem",
			"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
			"/etc/ssl/cert.pem",
			"/etc/ssl/certs",
		}
		for _, p := range paths {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
		return "system default"
	}
}
