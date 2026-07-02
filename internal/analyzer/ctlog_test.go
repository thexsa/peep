package analyzer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"math/big"
	"testing"
	"time"
)

func TestCheckCTLogsWithSCTs(t *testing.T) {
	// Build a synthetic SCT list with 2 entries
	sctList := buildSCTList(t, []sctTestEntry{
		{
			logID:     "0e5794bcf3aea93e331b2c9907b3f790df9bc23d713225dd21a925ac61c54e21", // Google Argon 2026h1
			timestamp: time.Date(2026, 6, 15, 8, 30, 0, 0, time.UTC),
		},
		{
			logID:     "cb38f715897c84a1445f5bc1ddfbc96ef29a59cd470a690585b0cb14c31458e7", // Cloudflare Nimbus 2026
			timestamp: time.Date(2026, 6, 15, 8, 31, 0, 0, time.UTC),
		},
	})

	// Wrap in ASN.1 OCTET STRING (as certs do)
	sctExtValue, err := asn1.Marshal(sctList)
	if err != nil {
		t.Fatal(err)
	}

	cert := createTestCert(t, []pkix.Extension{
		{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2},
			Value: sctExtValue,
		},
	})

	result := CheckCTLogs(cert, true)

	if !result.Found {
		t.Fatalf("expected Found=true, got false (error: %s)", result.Error)
	}
	if len(result.SCTs) != 2 {
		t.Fatalf("expected 2 SCTs, got %d", len(result.SCTs))
	}

	if result.SCTs[0].LogName != "Google Argon 2026h1" {
		t.Errorf("SCT 0 log name = %q, want %q", result.SCTs[0].LogName, "Google Argon 2026h1")
	}
	if result.SCTs[1].LogName != "Cloudflare Nimbus 2026" {
		t.Errorf("SCT 1 log name = %q, want %q", result.SCTs[1].LogName, "Cloudflare Nimbus 2026")
	}

	// Check timestamps
	if !result.SCTs[0].Timestamp.Equal(time.Date(2026, 6, 15, 8, 30, 0, 0, time.UTC)) {
		t.Errorf("SCT 0 timestamp = %v, expected 2026-06-15 08:30:00", result.SCTs[0].Timestamp)
	}
}

func TestCheckCTLogsNoSCTs(t *testing.T) {
	cert := createTestCert(t, nil)
	result := CheckCTLogs(cert, true)

	if result.Found {
		t.Fatal("expected Found=false for cert without SCTs")
	}
}

func TestCheckCTLogsPrivateCA(t *testing.T) {
	cert := createTestCert(t, nil)
	result := CheckCTLogs(cert, false)

	if !result.IsPrivateCA {
		t.Fatal("expected IsPrivateCA=true")
	}
	if result.Found {
		t.Fatal("expected Found=false for private CA")
	}
}

func TestCheckCTLogsNilCert(t *testing.T) {
	result := CheckCTLogs(nil, true)
	if result.Error == "" {
		t.Fatal("expected error for nil cert")
	}
}

// --- helpers ---

type sctTestEntry struct {
	logID     string
	timestamp time.Time
}

func buildSCTList(t *testing.T, entries []sctTestEntry) []byte {
	t.Helper()

	var scts []byte
	for _, e := range entries {
		sct := buildSCT(t, e.logID, e.timestamp)
		// Prepend SCT length (uint16)
		lenBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBuf, uint16(len(sct)))
		scts = append(scts, lenBuf...)
		scts = append(scts, sct...)
	}

	// Prepend list length (uint16)
	listLen := make([]byte, 2)
	binary.BigEndian.PutUint16(listLen, uint16(len(scts)))
	return append(listLen, scts...)
}

func buildSCT(t *testing.T, logIDHex string, ts time.Time) []byte {
	t.Helper()

	logID := hexDecode(t, logIDHex)
	if len(logID) != 32 {
		t.Fatalf("log ID must be 32 bytes, got %d", len(logID))
	}

	var buf []byte
	buf = append(buf, 0) // version = v1

	buf = append(buf, logID...) // 32 bytes log ID

	// Timestamp: ms since epoch (uint64)
	tsBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBuf, uint64(ts.UnixMilli()))
	buf = append(buf, tsBuf...)

	// Extensions length = 0
	buf = append(buf, 0, 0)

	// Hash algorithm (4 = SHA256) + Signature algorithm (3 = ECDSA)
	buf = append(buf, 4, 3)

	// Dummy signature (length + data)
	sig := []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01} // minimal DER ECDSA sig
	sigLen := make([]byte, 2)
	binary.BigEndian.PutUint16(sigLen, uint16(len(sig)))
	buf = append(buf, sigLen...)
	buf = append(buf, sig...)

	return buf
}

func hexDecode(t *testing.T, s string) []byte {
	t.Helper()
	var out []byte
	for i := 0; i < len(s); i += 2 {
		b := hexByte(s[i])<<4 | hexByte(s[i+1])
		out = append(out, b)
	}
	return out
}

func hexByte(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	default:
		return 0
	}
}

func createTestCert(t *testing.T, extraExtensions []pkix.Extension) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: extraExtensions,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	return cert
}
