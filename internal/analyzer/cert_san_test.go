package analyzer

import (
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

// buildTestPKI generates an in-memory Root CA -> Intermediate CA -> Leaf chain
// so tests can deterministically verify AnalyzeCert and AnalyzeChain across all flags.
func buildTestPKI(t *testing.T, leafCN string, dnsSANs []string, ipSANs []net.IP) (chain []*x509.Certificate, rootPEMPath string) {
	t.Helper()

	now := time.Now()

	// 1. Root CA (no SANs)
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate root key: %v", err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Peep Test Root CA"},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create root cert: %v", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("parse root cert: %v", err)
	}

	// 2. Intermediate CA (no SANs)
	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate intermediate key: %v", err)
	}
	interTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Peep Test Issuing CA"},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, rootCert, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create intermediate cert: %v", err)
	}
	interCert, err := x509.ParseCertificate(interDER)
	if err != nil {
		t.Fatalf("parse intermediate cert: %v", err)
	}

	// 3. Leaf cert
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: leafCN},
		NotBefore:    now.Add(-1 * time.Hour),
		NotAfter:     now.Add(180 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsSANs,
		IPAddresses:  ipSANs,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, interCert, &leafKey.PublicKey, interKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}

	// Write root PEM for --ca-bundle testing
	tmpDir := t.TempDir()
	pemPath := filepath.Join(tmpDir, "root.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	if err := os.WriteFile(pemPath, pemBytes, 0600); err != nil {
		t.Fatalf("write root pem: %v", err)
	}

	return []*x509.Certificate{leafCert, interCert}, pemPath
}

func TestMissingSANs_CNFallbackRejectedDeterministically(t *testing.T) {
	certs, rootPEM := buildTestPKI(t, "legacy.corp.example.com", nil, nil)
	state := &tls.ConnectionState{
		Version:          tls.VersionTLS13,
		CipherSuite:      tls.TLS_AES_256_GCM_SHA384,
		PeerCertificates: certs,
	}

	t.Run("standard verification with custom CA bundle", func(t *testing.T) {
		chain := AnalyzeChain(state, "legacy.corp.example.com", false, rootPEM)
		leaf := chain.Certificates[0]

		if !leaf.MissingSANs {
			t.Errorf("expected MissingSANs=true on SAN-less leaf cert")
		}
		if !leaf.CNOnlyMatch {
			t.Errorf("expected CNOnlyMatch=true when CN matches targetHost and SANs are absent")
		}
		if leaf.HostnameMatch {
			t.Errorf("expected HostnameMatch=false when relying on CN fallback")
		}
		if leaf.OverallGrade != WrittenInCrayon {
			t.Errorf("expected leaf OverallGrade=WrittenInCrayon, got %v", leaf.OverallGrade)
		}
		if chain.TrustStoreVerified {
			t.Errorf("expected TrustStoreVerified=false for SAN-less leaf cert")
		}
		if !strings.Contains(chain.VerificationError, "Common Name") && !strings.Contains(chain.VerificationError, "SAN") {
			t.Errorf("expected VerificationError to mention Common Name or SANs, got %q", chain.VerificationError)
		}
		if chain.OverallGrade != WrittenInCrayon {
			t.Errorf("expected chain OverallGrade=WrittenInCrayon, got %v", chain.OverallGrade)
		}
		// Intermediate CA should NOT be flagged for missing SANs
		inter := chain.Certificates[1]
		if inter.MissingSANs || inter.CNOnlyMatch || !inter.HostnameMatch {
			t.Errorf("non-leaf CA cert should not be flagged for SANs: MissingSANs=%v CNOnlyMatch=%v HostnameMatch=%v",
				inter.MissingSANs, inter.CNOnlyMatch, inter.HostnameMatch)
		}
	})

	t.Run("insecure mode (--insecure / -i / --blindfold) still flags missing SANs", func(t *testing.T) {
		chain := AnalyzeChain(state, "legacy.corp.example.com", true, "")
		leaf := chain.Certificates[0]

		if !leaf.MissingSANs || !leaf.CNOnlyMatch || leaf.HostnameMatch {
			t.Errorf("insecure mode masked SAN/CN state: MissingSANs=%v CNOnlyMatch=%v HostnameMatch=%v",
				leaf.MissingSANs, leaf.CNOnlyMatch, leaf.HostnameMatch)
		}
		if leaf.OverallGrade != WrittenInCrayon {
			t.Errorf("expected leaf OverallGrade=WrittenInCrayon in --insecure mode, got %v", leaf.OverallGrade)
		}
		if chain.OverallGrade != WrittenInCrayon {
			t.Errorf("expected chain OverallGrade=WrittenInCrayon in --insecure mode, got %v", chain.OverallGrade)
		}
	})
}

func TestMissingSANs_IPInCommonName(t *testing.T) {
	certs, _ := buildTestPKI(t, "10.20.30.40", nil, nil)
	leaf := AnalyzeCert(certs[0], 0, len(certs), "10.20.30.40")

	if !leaf.MissingSANs {
		t.Errorf("expected MissingSANs=true")
	}
	if !leaf.CNOnlyMatch {
		t.Errorf("expected CNOnlyMatch=true when IP is placed in CN instead of IP SAN")
	}
	if leaf.HostnameMatch {
		t.Errorf("expected HostnameMatch=false")
	}
	if leaf.OverallGrade != WrittenInCrayon {
		t.Errorf("expected OverallGrade=WrittenInCrayon, got %v", leaf.OverallGrade)
	}
}

func TestCNOnlyMatch_WhenOtherSANsExist(t *testing.T) {
	certs, rootPEM := buildTestPKI(t, "api.corp.example.com", []string{"www.corp.example.com"}, nil)
	state := &tls.ConnectionState{
		Version:          tls.VersionTLS13,
		CipherSuite:      tls.TLS_AES_256_GCM_SHA384,
		PeerCertificates: certs,
	}

	chain := AnalyzeChain(state, "api.corp.example.com", false, rootPEM)
	leaf := chain.Certificates[0]

	if leaf.MissingSANs {
		t.Errorf("expected MissingSANs=false when other DNS SANs are present")
	}
	if !leaf.CNOnlyMatch {
		t.Errorf("expected CNOnlyMatch=true when hostname matches CN but is missing from SANs")
	}
	if leaf.HostnameMatch {
		t.Errorf("expected HostnameMatch=false")
	}
	if chain.TrustStoreVerified {
		t.Errorf("expected TrustStoreVerified=false")
	}
	if chain.OverallGrade != WrittenInCrayon {
		t.Errorf("expected chain OverallGrade=WrittenInCrayon, got %v", chain.OverallGrade)
	}
}

func TestValidSAN_EmptyCommonNamePasses(t *testing.T) {
	certs, rootPEM := buildTestPKI(t, "", []string{"modern.example.com"}, nil)
	state := &tls.ConnectionState{
		Version:          tls.VersionTLS13,
		CipherSuite:      tls.TLS_AES_256_GCM_SHA384,
		PeerCertificates: certs,
	}

	chain := AnalyzeChain(state, "modern.example.com", false, rootPEM)
	leaf := chain.Certificates[0]

	if leaf.MissingSANs || leaf.CNOnlyMatch || !leaf.HostnameMatch {
		t.Errorf("modern SAN-only cert with empty CN failed: MissingSANs=%v CNOnlyMatch=%v HostnameMatch=%v",
			leaf.MissingSANs, leaf.CNOnlyMatch, leaf.HostnameMatch)
	}
	if !chain.TrustStoreVerified {
		t.Errorf("expected TrustStoreVerified=true, got error: %s", chain.VerificationError)
	}
	if chain.OverallGrade != MainCharacterEnergy {
		t.Errorf("expected MainCharacterEnergy, got %v", chain.OverallGrade)
	}
}
