package analyzer

import (
	"crypto/tls"
)

// AnalyzeHandshake grades the TLS handshake parameters.
func AnalyzeHandshake(state *tls.ConnectionState) HandshakeAnalysis {
	analysis := HandshakeAnalysis{
		TLSVersion:     getTLSVersionName(state.Version),
		TLSVersionRaw:  state.Version,
		CipherSuite:    tls.CipherSuiteName(state.CipherSuite),
		CipherSuiteRaw: state.CipherSuite,
	}

	analysis.VersionGrade = gradeTLSVersion(state.Version)
	analysis.CipherGrade = gradeCipherSuite(state.CipherSuite)
	analysis.OverallGrade = worstOf(analysis.VersionGrade, analysis.CipherGrade)

	return analysis
}

func getTLSVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLSv1.3"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS10:
		return "TLSv1.0"
	default:
		return "Unknown"
	}
}

func gradeTLSVersion(v uint16) HealthStatus {
	switch v {
	case tls.VersionTLS13:
		return MainCharacterEnergy
	case tls.VersionTLS12:
		return MainCharacterEnergy
	case tls.VersionTLS11:
		return WrittenInCrayon
	case tls.VersionTLS10:
		return WrittenInCrayon
	default:
		return WrittenInCrayon
	}
}

// gradeCipherSuite grades a cipher suite by its security properties.
func gradeCipherSuite(id uint16) HealthStatus {
	name := tls.CipherSuiteName(id)

	// Check against known secure suites first
	for _, suite := range tls.CipherSuites() {
		if suite.ID == id {
			return MainCharacterEnergy
		}
	}

	// Check insecure suites
	for _, suite := range tls.InsecureCipherSuites() {
		if suite.ID == id {
			return WrittenInCrayon
		}
	}

	// Heuristic-based grading from the name
	_ = name
	return MallCopCredentials
}
