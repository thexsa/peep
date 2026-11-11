package analyzer

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"runtime"
)

// GetSystemCAStorePath returns the filesystem path to the system's CA certificate
// trust store, or a descriptive string for OS-managed stores (macOS Keychain, Windows CertStore).
// It respects SSL_CERT_FILE and SSL_CERT_DIR environment variables across all platforms.
func GetSystemCAStorePath() string {
	if f := os.Getenv("SSL_CERT_FILE"); f != "" {
		if info, err := os.Stat(f); err == nil && !info.IsDir() {
			return f
		}
	}
	if d := os.Getenv("SSL_CERT_DIR"); d != "" {
		for _, dir := range filepath.SplitList(d) {
			if dir == "" {
				continue
			}
			if info, err := os.Stat(dir); err == nil && info.IsDir() {
				return d
			}
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

// loadSystemRootPool loads the root CA pool for chain verification when --ca-bundle
// is not set. It honors SSL_CERT_FILE and SSL_CERT_DIR consistently on all OSes
// (including macOS and Windows, where Go's SystemCertPool ignores them), and falls
// back on AIX to IBM AIX Toolbox's CA bundle when /var/ssl/certs/ca-bundle.crt is absent.
func loadSystemRootPool() *x509.CertPool {
	if f := os.Getenv("SSL_CERT_FILE"); f != "" {
		if pool, err := loadCABundle(f); err == nil {
			return pool
		}
	}
	if d := os.Getenv("SSL_CERT_DIR"); d != "" {
		if pool, ok := loadCADirPool(d); ok {
			return pool
		}
	}

	if runtime.GOOS == "aix" {
		if _, err := os.Stat("/var/ssl/certs/ca-bundle.crt"); os.IsNotExist(err) {
			const aixToolboxBundle = "/opt/freeware/etc/ssl/certs/ca-bundle.crt"
			if pool, loadErr := loadCABundle(aixToolboxBundle); loadErr == nil {
				return pool
			}
		}
	}

	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		if runtime.GOOS == "aix" {
			if pool, loadErr := loadCABundle("/opt/freeware/etc/ssl/certs/ca-bundle.crt"); loadErr == nil {
				return pool
			}
		}
		return x509.NewCertPool()
	}
	return roots
}

// loadCADirPool loads all readable certificate files from a PATH-list of directories
// (colon-separated on Unix, semicolon-separated on Windows).
func loadCADirPool(dirList string) (*x509.CertPool, bool) {
	pool := x509.NewCertPool()
	added := false

	for _, dir := range filepath.SplitList(dirList) {
		if dir == "" {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			fullPath := filepath.Join(dir, entry.Name())
			data, readErr := os.ReadFile(fullPath)
			if readErr != nil {
				continue
			}
			if pool.AppendCertsFromPEM(data) {
				added = true
				continue
			}
			if cert, parseErr := x509.ParseCertificate(data); parseErr == nil {
				pool.AddCert(cert)
				added = true
			}
		}
	}

	return pool, added
}
