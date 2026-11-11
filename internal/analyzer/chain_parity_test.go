package analyzer

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func makeParityTestCA(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatalf("rand.Int: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	signerCert := tmpl
	signerKey := key
	if parent != nil {
		signerCert = parent
		signerKey = parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("CreateCertificate(%s): %v", cn, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate(%s): %v", cn, err)
	}
	return cert, key
}

func makeParityTestLeaf(t *testing.T, cn string, dnsNames []string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatalf("rand.Int: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("CreateCertificate(leaf): %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate(leaf): %v", err)
	}
	return cert, key
}

func TestSelectWireCompleteChain(t *testing.T) {
	root, rootKey := makeParityTestCA(t, "Parity Root CA", nil, nil)
	inter2, inter2Key := makeParityTestCA(t, "Parity Intermediate 2 CA", root, rootKey)
	inter1, inter1Key := makeParityTestCA(t, "Parity Intermediate 1 CA", inter2, inter2Key)
	leaf, _ := makeParityTestLeaf(t, "app.example.com", []string{"app.example.com"}, inter1, inter1Key)

	t.Run("rejects OS-synthesized intermediate on multi-cert chain", func(t *testing.T) {
		// Server sent [leaf, inter1] (omitting inter2), while macOS SecTrust / Windows CryptoAPI
		// silently resolved inter2 via AIA/cache to produce verified chain [leaf, inter1, inter2, root].
		presented := []*x509.Certificate{leaf, inter1}
		verifiedChains := [][]*x509.Certificate{
			{leaf, inter1, inter2, root},
		}

		selected, missing := selectWireCompleteChain(verifiedChains, presented)
		if selected != nil {
			t.Fatalf("expected nil selected chain when inter2 was omitted on the wire, got len=%d", len(selected))
		}
		if missing != "Parity Intermediate 2 CA" {
			t.Fatalf("expected missing intermediate name %q, got %q", "Parity Intermediate 2 CA", missing)
		}
	})

	t.Run("accepts wire-complete multi-intermediate chain", func(t *testing.T) {
		presented := []*x509.Certificate{leaf, inter1, inter2}
		verifiedChains := [][]*x509.Certificate{
			{leaf, inter1, inter2, root},
		}

		selected, missing := selectWireCompleteChain(verifiedChains, presented)
		if selected == nil {
			t.Fatalf("expected wire-complete chain to be accepted, got nil (missing=%q)", missing)
		}
		if missing != "" {
			t.Fatalf("expected empty missing string, got %q", missing)
		}
	})

	t.Run("selects wire-complete alternate path on cross-signed root", func(t *testing.T) {
		altRoot, _ := makeParityTestCA(t, "Direct Trusted Root CA", nil, nil)
		crossInter, _ := makeParityTestCA(t, "Cached Cross-Sign CA", root, rootKey)

		// Server sent [leaf, inter1]. Path 0 goes through an unpresented cross-signed CA,
		// while Path 1 terminates directly at altRoot using only inter1.
		presented := []*x509.Certificate{leaf, inter1}
		verifiedChains := [][]*x509.Certificate{
			{leaf, inter1, crossInter, root},
			{leaf, inter1, altRoot},
		}

		selected, missing := selectWireCompleteChain(verifiedChains, presented)
		if selected == nil {
			t.Fatalf("expected second wire-complete path to be chosen, got nil (missing=%q)", missing)
		}
		if gotRoot := selected[len(selected)-1].Subject.CommonName; gotRoot != "Direct Trusted Root CA" {
			t.Fatalf("expected Direct Trusted Root CA, got %q", gotRoot)
		}
	})
}

func TestSSLCertFileAndDirParity(t *testing.T) {
	root, rootKey := makeParityTestCA(t, "Env Parity Root CA", nil, nil)
	inter, interKey := makeParityTestCA(t, "Env Parity Issuing CA", root, rootKey)
	leaf, _ := makeParityTestLeaf(t, "envcheck.example.com", []string{"envcheck.example.com"}, inter, interKey)

	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})
	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf, inter},
	}

	t.Run("SSL_CERT_FILE honored across all OSes", func(t *testing.T) {
		tmpDir := t.TempDir()
		bundleFile := filepath.Join(tmpDir, "custom-ca.pem")
		if err := os.WriteFile(bundleFile, rootPEM, 0644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		t.Setenv("SSL_CERT_FILE", bundleFile)
		t.Setenv("SSL_CERT_DIR", "")

		if got := GetSystemCAStorePath(); got != bundleFile {
			t.Fatalf("GetSystemCAStorePath() = %q, want %q", got, bundleFile)
		}

		chain := AnalyzeChain(state, "envcheck.example.com", false, "")
		if !chain.TrustStoreVerified {
			t.Fatalf("expected TrustStoreVerified=true via SSL_CERT_FILE, got false (err=%q)", chain.VerificationError)
		}
		if chain.SystemCAStorePath != bundleFile {
			t.Fatalf("chain.SystemCAStorePath = %q, want %q", chain.SystemCAStorePath, bundleFile)
		}
	})

	t.Run("SSL_CERT_DIR honored with OS path list separator", func(t *testing.T) {
		emptyDir := t.TempDir()
		certDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(certDir, "env-root.crt"), rootPEM, 0644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		dirList := emptyDir + string(os.PathListSeparator) + certDir
		t.Setenv("SSL_CERT_FILE", "")
		t.Setenv("SSL_CERT_DIR", dirList)

		if got := GetSystemCAStorePath(); got != dirList {
			t.Fatalf("GetSystemCAStorePath() = %q, want %q", got, dirList)
		}

		chain := AnalyzeChain(state, "envcheck.example.com", false, "")
		if !chain.TrustStoreVerified {
			t.Fatalf("expected TrustStoreVerified=true via SSL_CERT_DIR, got false (err=%q)", chain.VerificationError)
		}
	})
}

func TestWindowsAndUnixLDAPCRLCommands(t *testing.T) {
	uri := "ldap:///CN=CorpIssuingCA,CN=AIA,CN=Public%20Key%20Services,DC=corp,DC=local?certificateRevocationList"

	unixCmd := LDAPSearchCommand(uri)
	if !strings.Contains(unixCmd, "ldapsearch -x -H") || !strings.Contains(unixCmd, uri) {
		t.Fatalf("unexpected LDAPSearchCommand: %s", unixCmd)
	}

	winCmd := WindowsCRLCommand(uri)
	wantWin := `certutil -URL "` + uri + `"`
	if winCmd != wantWin {
		t.Fatalf("WindowsCRLCommand = %q, want %q", winCmd, wantWin)
	}
}

func TestEnumerateCiphersWithProto_STARTTLS(t *testing.T) {
	root, rootKey := makeParityTestCA(t, "SMTP Test Root", nil, nil)
	leaf, leafKey := makeParityTestLeaf(t, "mail.example.test", []string{"127.0.0.1", "mail.example.test"}, root, rootKey)

	tlsCert := tls.Certificate{
		Certificate: [][]byte{leaf.Raw},
		PrivateKey:  leafKey,
	}
	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				_, _ = c.Write([]byte("220 smtp.example.test ESMTP\r\n"))
				r := bufio.NewReader(c)
				for {
					line, readErr := r.ReadString('\n')
					if readErr != nil {
						return
					}
					upper := strings.ToUpper(strings.TrimSpace(line))
					switch {
					case strings.HasPrefix(upper, "EHLO") || strings.HasPrefix(upper, "HELO"):
						_, _ = c.Write([]byte("250-smtp.example.test\r\n250 STARTTLS\r\n"))
					case upper == "STARTTLS":
						_, _ = c.Write([]byte("220 Ready to start TLS\r\n"))
						tlsConn := tls.Server(c, serverTLS)
						_ = tlsConn.Handshake()
						return
					default:
						_, _ = c.Write([]byte("500 Unknown\r\n"))
					}
				}
			}(conn)
		}
	}()

	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}

	enum := EnumerateCiphersWithProto("127.0.0.1", port, "smtp", 1500*time.Millisecond)
	if len(enum.SupportedSuites) == 0 {
		t.Fatalf("expected supported cipher suites over SMTP STARTTLS, got 0")
	}

	foundSupportedVersion := false
	for _, v := range enum.TLSVersions {
		if (v.Version == "TLSv1.3" || v.Version == "TLSv1.2") && v.Supported {
			foundSupportedVersion = true
		}
	}
	if !foundSupportedVersion {
		t.Fatalf("expected TLSv1.2 or TLSv1.3 supported over SMTP STARTTLS, got %+v", enum.TLSVersions)
	}
}
