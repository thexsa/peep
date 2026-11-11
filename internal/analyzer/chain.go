package analyzer

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// AnalyzeChain performs a full analysis of the certificate chain.
func AnalyzeChain(state *tls.ConnectionState, targetHost string, skipVerify bool, caBundlePath string) ChainAnalysis {
	certs := state.PeerCertificates
	totalCerts := len(certs)
	analysis := ChainAnalysis{ChainLength: totalCerts}

	for i, cert := range certs {
		certAnalysis := AnalyzeCert(cert, i, totalCerts, targetHost)
		analysis.Certificates = append(analysis.Certificates, certAnalysis)
	}

	analysis.ChainOrderCorrect = verifyChainOrder(certs)
	analysis.HasWrongIntermediate = checkWrongIntermediate(certs)
	analysis.HasMissingIntermediate = !analysis.HasWrongIntermediate && checkMissingIntermediate(certs)
	analysis.HasUnnecessaryRoot = checkUnnecessaryRoot(certs)
	analysis.LeafOnlyMissingIntermediate = checkLeafOnlyMissingIntermediate(certs)

	// NoIssuingCAInResponse: true if the server sent only the leaf cert
	// (regardless of whether it's self-signed) or if intermediates are missing.
	// But NOT if the server sent a wrong intermediate — that's a different problem.
	if (len(certs) == 1 || analysis.HasMissingIntermediate) && !analysis.HasWrongIntermediate {
		analysis.NoIssuingCAInResponse = true
	}

	// Always record the CA store path (even if verification fails or is skipped)
	// so the UI can display which trust store was/would be used.
	if caBundlePath != "" {
		analysis.CustomTrustStore = true
		analysis.CustomTrustStorePath = caBundlePath
	} else {
		analysis.SystemCAStorePath = GetSystemCAStorePath()
	}

	if !skipVerify && totalCerts > 0 {
		var omittedWireIntermediate bool
		analysis.TrustStoreVerified, analysis.VerificationError,
			analysis.TrustedRootName, analysis.TrustedRootSerial,
			analysis.TrustedRootFingerprint, omittedWireIntermediate = verifyTrustStoreWithWireCheck(certs, targetHost, caBundlePath)
		if omittedWireIntermediate && !analysis.HasWrongIntermediate {
			analysis.HasMissingIntermediate = true
			analysis.NoIssuingCAInResponse = true
		}
	}

	analysis.OverallGrade = gradeChain(analysis)
	return analysis
}

func verifyChainOrder(certs []*x509.Certificate) bool {
	for i := 0; i < len(certs)-1; i++ {
		if certs[i].Issuer.String() != certs[i+1].Subject.String() {
			return false
		}
	}
	return true
}

func checkMissingIntermediate(certs []*x509.Certificate) bool {
	if len(certs) == 1 && certs[0].Subject.String() != certs[0].Issuer.String() {
		return true
	}
	if len(certs) <= 1 {
		return false
	}
	for i := 0; i < len(certs)-1; i++ {
		if err := certs[i].CheckSignatureFrom(certs[i+1]); err != nil {
			return true
		}
	}
	return false
}

// checkLeafOnlyMissingIntermediate detects when the server sends only a leaf cert
// and the leaf's issuer is NOT a root CA (meaning the intermediate is missing).
// In this case, clients need both the intermediate AND root in their trust store,
// which is incorrect — only the root should be needed.
func checkLeafOnlyMissingIntermediate(certs []*x509.Certificate) bool {
	if len(certs) != 1 {
		return false
	}
	leaf := certs[0]
	// If self-signed, it's a self-signed leaf — different problem
	if leaf.Subject.String() == leaf.Issuer.String() {
		return false
	}
	// The leaf has an issuer, and it's not itself. The issuer could be:
	// - A root CA (acceptable, though unusual)
	// - An intermediate CA (BAD — the intermediate should be in the chain)
	// We can't 100% know from just the leaf, but if the leaf is NOT CA
	// and its issuer is NOT in the system trust store as a root, it's likely
	// an intermediate. The HasMissingIntermediate flag already catches the
	// general case; this flag specifically calls out the leaf-only scenario.
	return true
}

// checkWrongIntermediate detects when the server sends an intermediate
// whose subject DN matches the leaf's issuer DN, but whose public key
// did NOT sign the leaf certificate. This typically happens when:
//   - The CA was renewed with a new key pair (re-keyed)
//   - The server admin updated the intermediate bundle but didn't re-issue the leaf
//   - The wrong intermediate cert was grabbed during renewal
func checkWrongIntermediate(certs []*x509.Certificate) bool {
	if len(certs) < 2 {
		return false
	}
	for i := 0; i < len(certs)-1; i++ {
		child := certs[i]
		parent := certs[i+1]
		// Issuer DN matches (server thinks this is the right CA)...
		if child.Issuer.String() == parent.Subject.String() {
			// ...but the signature doesn't verify (wrong key)
			if err := child.CheckSignatureFrom(parent); err != nil {
				return true
			}
		}
	}
	return false
}

func checkUnnecessaryRoot(certs []*x509.Certificate) bool {
	if len(certs) <= 1 {
		return false
	}
	last := certs[len(certs)-1]
	return last.Subject.String() == last.Issuer.String() && last.IsCA
}

// verifyTrustStore checks the chain against the system trust store.
// Returns: verified, error, rootName, rootSerial, rootFingerprint.
func verifyTrustStore(certs []*x509.Certificate, hostname string, caBundlePath string) (bool, string, string, string, string) {
	verified, errStr, rootName, rootSerial, rootFP, _ := verifyTrustStoreWithWireCheck(certs, hostname, caBundlePath)
	return verified, errStr, rootName, rootSerial, rootFP
}

// verifyTrustStoreWithWireCheck checks the chain against the trust store and additionally
// enforces that every intermediate CA in the verified path was actually presented on the
// wire by the server (preventing macOS Security.framework or Windows CryptoAPI from
// silently resolving missing intermediates via AIA or local OS caches).
func verifyTrustStoreWithWireCheck(certs []*x509.Certificate, hostname string, caBundlePath string) (bool, string, string, string, string, bool) {
	if len(certs) == 0 {
		return false, "no certificates presented", "", "", "", false
	}

	// If the server sent only a leaf cert and it's not self-signed, the chain
	// is incomplete. Don't even ask Go's Verify() — macOS will find the
	// intermediate in its Keychain cache and say "it's fine." It's not fine.
	if len(certs) == 1 {
		leaf := certs[0]
		if leaf.Subject.String() != leaf.Issuer.String() {
			return false, "incomplete chain: server sent only the leaf certificate, no intermediate CA", "", "", "", true
		}
	}

	// Verify that the chain the server sent is internally consistent.
	// Walk each cert pair and confirm the child's signature verifies against
	// the parent's key. This catches wrong intermediates and broken chains
	// regardless of what the OS trust store has cached.
	for i := 0; i < len(certs)-1; i++ {
		child := certs[i]
		parent := certs[i+1]
		if err := child.CheckSignatureFrom(parent); err != nil {
			return false, fmt.Sprintf("signature verification failed at depth %d: %s did not sign %s",
				i, parent.Subject.CommonName, child.Subject.CommonName), "", "", "", false
		}
	}

	// Build root cert pool — either from a custom CA bundle or from the system.
	var roots *x509.CertPool
	if caBundlePath != "" {
		// Custom CA bundle replaces the system trust store (like curl --cacert).
		// Accepts .pem, .crt, .cer (PEM-encoded), and .der (DER-encoded) files.
		var err error
		roots, err = loadCABundle(caBundlePath)
		if err != nil {
			return false, fmt.Sprintf("failed to load CA bundle %q: %v", caBundlePath, err), "", "", "", false
		}
	} else {
		roots = loadSystemRootPool()
	}

	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	opts := x509.VerifyOptions{
		DNSName:       hostname,
		Intermediates: intermediates,
		Roots:         roots,
	}
	chains, err := certs[0].Verify(opts)
	if err != nil {
		return false, err.Error(), "", "", "", false
	}

	// Enforce wire-completeness across all OSes: on macOS and Windows, the OS
	// platform verifier can synthesize missing higher-level intermediates via AIA
	// fetching or cached intermediates even when len(certs) >= 2. Require at least
	// one verified chain whose non-root intermediates were all presented by the server.
	wireChain, missingIntermediate := selectWireCompleteChain(chains, certs)
	if wireChain == nil && missingIntermediate != "" {
		return false, fmt.Sprintf(
			"incomplete chain: server omitted intermediate CA %q (resolved only via OS cache/AIA; strict TLS clients will fail)",
			missingIntermediate,
		), "", "", "", true
	}

	// Enforce strict RFC 6125 SAN-only hostname verification on ALL OSes.
	// On Windows, Go's SystemCertPool delegates chain verification to Windows
	// CryptoAPI (CertVerifyCertificateChainPolicy), which silently allows falling
	// back to Subject CommonName when a certificate has no SAN extension.
	// Explicitly running VerifyHostname ensures Windows rejects missing-SAN /
	// CN-only certs identically to macOS, Linux, AIX, and modern browsers.
	if hostname != "" {
		if err := certs[0].VerifyHostname(hostname); err != nil {
			return false, err.Error(), "", "", "", false
		}
	} else if len(certs[0].DNSNames) == 0 && len(certs[0].IPAddresses) == 0 {
		return false, "x509: leaf certificate has no Subject Alternative Names (SANs)", "", "", "", false
	}

	// Extract the trusted root from the verified wire-complete chain.
	var rootName, rootSerial, rootFP string
	if len(wireChain) > 0 {
		root := wireChain[len(wireChain)-1]
		rootName = root.Subject.CommonName
		if rootName == "" {
			rootName = root.Subject.String()
		}
		rootSerial = fmt.Sprintf("%X", root.SerialNumber)
		hash := sha256.Sum256(root.Raw)
		rootFP = fmt.Sprintf("%X", hash)
	}

	return true, "", rootName, rootSerial, rootFP, false
}

// selectWireCompleteChain returns the first verified chain in chains whose
// non-root intermediate certificates (chain[1 : len(chain)-1]) were all actually
// presented by the server in presentedCerts[1:]. If no verified chain is
// wire-complete, it returns (nil, omittedIntermediateName).
func selectWireCompleteChain(chains [][]*x509.Certificate, presentedCerts []*x509.Certificate) ([]*x509.Certificate, string) {
	if len(chains) == 0 {
		return nil, ""
	}

	wireIntermediates := presentedCerts[1:]
	firstMissing := ""

	for _, ch := range chains {
		if len(ch) <= 2 {
			// Either [Leaf] (directly trusted) or [Leaf, Root] (no intermediates).
			return ch, ""
		}

		allOnWire := true
		for _, inter := range ch[1 : len(ch)-1] {
			if !certInSlice(inter, wireIntermediates) {
				allOnWire = false
				if firstMissing == "" {
					firstMissing = inter.Subject.CommonName
					if firstMissing == "" {
						firstMissing = inter.Subject.String()
					}
				}
				break
			}
		}
		if allOnWire {
			return ch, ""
		}
	}

	return nil, firstMissing
}

func certInSlice(target *x509.Certificate, list []*x509.Certificate) bool {
	for _, c := range list {
		if target.Equal(c) {
			return true
		}
	}
	return false
}

func gradeChain(a ChainAnalysis) HealthStatus {
	grade := MainCharacterEnergy
	for _, cert := range a.Certificates {
		grade = worst(grade, cert.OverallGrade)
	}
	if !a.ChainOrderCorrect {
		grade = worst(grade, WrittenInCrayon)
	}
	if a.HasMissingIntermediate {
		grade = worst(grade, WrittenInCrayon)
	}
	if a.HasWrongIntermediate {
		grade = worst(grade, WrittenInCrayon)
	}
	// NOTE: HasUnnecessaryRoot is NOT graded here — it's a warning-level finding
	// handled by the CHAIN_UNNECESSARY_ROOT warning code in the education package.
	// Keeping it out of the chain grade allows the dual verdict system to correctly
	// distinguish browser (pass — browsers ignore the extra root) from service
	// (warn — some strict clients flag it).
	if a.LeafOnlyMissingIntermediate {
		grade = worst(grade, WrittenInCrayon)
	}
	if a.VerificationError != "" {
		grade = worst(grade, WrittenInCrayon)
	}
	return grade
}

// loadCABundle loads a CA certificate bundle from a file.
// Supports PEM-encoded files (.pem, .crt, .cer) and DER-encoded files (.der, .cer).
// The file may contain multiple certificates (PEM bundles).
func loadCABundle(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read file: %w", err)
	}

	pool := x509.NewCertPool()
	count := 0

	ext := strings.ToLower(filepath.Ext(path))

	// Try PEM first — works for .pem, .crt, .cer (most common)
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		pool.AddCert(cert)
		count++
	}

	// If no PEM certs found and the extension suggests DER, try DER parsing
	if count == 0 && (ext == ".der" || ext == ".cer" || ext == ".crt") {
		cert, err := x509.ParseCertificate(data)
		if err != nil {
			return nil, fmt.Errorf("file contains no valid PEM or DER certificates")
		}
		pool.AddCert(cert)
		count++
	}

	if count == 0 {
		return nil, fmt.Errorf("no valid certificates found in %s", filepath.Base(path))
	}

	return pool, nil
}
