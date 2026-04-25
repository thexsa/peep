package analyzer

import (
	"crypto/tls"
	"crypto/x509"
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
	analysis.HasMissingIntermediate = checkMissingIntermediate(certs)
	analysis.HasUnnecessaryRoot = checkUnnecessaryRoot(certs)

	if !skipVerify && totalCerts > 0 {
		analysis.TrustStoreVerified, analysis.VerificationError = verifyTrustStore(certs, targetHost)
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

func checkUnnecessaryRoot(certs []*x509.Certificate) bool {
	if len(certs) <= 1 {
		return false
	}
	last := certs[len(certs)-1]
	return last.Subject.String() == last.Issuer.String() && last.IsCA
}

func verifyTrustStore(certs []*x509.Certificate, hostname string) (bool, string) {
	if len(certs) == 0 {
		return false, "no certificates presented"
	}
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	opts := x509.VerifyOptions{
		DNSName:       hostname,
		Intermediates: intermediates,
	}
	_, err := certs[0].Verify(opts)
	if err != nil {
		return false, err.Error()
	}
	return true, ""
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
	if a.HasUnnecessaryRoot {
		grade = worst(grade, MallCopCredentials)
	}
	if a.VerificationError != "" {
		grade = worst(grade, WrittenInCrayon)
	}
	return grade
}
