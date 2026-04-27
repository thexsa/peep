package analyzer

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

// AnalyzeChain performs a full analysis of the certificate chain.
func AnalyzeChain(state *tls.ConnectionState, targetHost string, skipVerify bool) ChainAnalysis {
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

	if !skipVerify && totalCerts > 0 {
		analysis.TrustStoreVerified, analysis.VerificationError,
			analysis.TrustedRootName, analysis.TrustedRootSerial,
			analysis.TrustedRootFingerprint = verifyTrustStore(certs, targetHost)
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
func verifyTrustStore(certs []*x509.Certificate, hostname string) (bool, string, string, string, string) {
	if len(certs) == 0 {
		return false, "no certificates presented", "", "", ""
	}

	// If the server sent only a leaf cert and it's not self-signed, the chain
	// is incomplete. Don't even ask Go's Verify() — macOS will find the
	// intermediate in its Keychain cache and say "it's fine." It's not fine.
	if len(certs) == 1 {
		leaf := certs[0]
		if leaf.Subject.String() != leaf.Issuer.String() {
			return false, "incomplete chain: server sent only the leaf certificate, no intermediate CA", "", "", ""
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
				i, parent.Subject.CommonName, child.Subject.CommonName), "", "", ""
		}
	}

	// Then verify against the system trust store. Explicitly load the root
	// pool so Go uses its own chain builder instead of the macOS platform
	// verifier (which can fetch intermediates via AIA and use cached certs).
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
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
		return false, err.Error(), "", "", ""
	}

	// Extract the trusted root from the verified chain.
	// The root is the last cert in the first verified chain.
	var rootName, rootSerial, rootFP string
	if len(chains) > 0 && len(chains[0]) > 0 {
		root := chains[0][len(chains[0])-1]
		rootName = root.Subject.CommonName
		rootSerial = fmt.Sprintf("%X", root.SerialNumber)
		hash := sha256.Sum256(root.Raw)
		rootFP = fmt.Sprintf("%X", hash)
	}

	return true, "", rootName, rootSerial, rootFP
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
	if a.HasUnnecessaryRoot {
		grade = worst(grade, MallCopCredentials)
	}
	if a.LeafOnlyMissingIntermediate {
		grade = worst(grade, WrittenInCrayon)
	}
	if a.VerificationError != "" {
		grade = worst(grade, WrittenInCrayon)
	}
	return grade
}
