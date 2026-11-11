package education

import (
	"testing"

	"github.com/thexsa/peep/internal/analyzer"
)

func TestMissingSANSayingsPool(t *testing.T) {
	if len(MissingSANSayings) < 25 {
		t.Fatalf("expected at least 25 sarcastic remarks in MissingSANSayings, got %d", len(MissingSANSayings))
	}

	seen := make(map[string]bool, len(MissingSANSayings))
	for i, s := range MissingSANSayings {
		if s == "" {
			t.Errorf("MissingSANSayings[%d] is empty", i)
		}
		if seen[s] {
			t.Errorf("duplicate remark in MissingSANSayings at index %d: %q", i, s)
		}
		seen[s] = true
	}

	// Verify random order / variety over repeated draws
	picked := make(map[string]bool)
	for i := 0; i < 100; i++ {
		picked[pick(MissingSANSayings)] = true
	}
	if len(picked) < 10 {
		t.Errorf("expected random variety across draws, only saw %d distinct remarks in 100 picks", len(picked))
	}
}

func TestMissingSANsWarnings_DeterministicAcrossFlags(t *testing.T) {
	sayingsSet := make(map[string]bool, len(MissingSANSayings))
	for _, s := range MissingSANSayings {
		sayingsSet[s] = true
	}

	for _, internalCA := range []bool{false, true} {
		report := &analyzer.DiagnosticReport{
			Handshake: analyzer.HandshakeAnalysis{
				TLSVersion:   "TLSv1.3",
				CipherSuite:  "TLS_AES_256_GCM_SHA384",
				CipherGrade:  analyzer.MainCharacterEnergy,
				VersionGrade: analyzer.MainCharacterEnergy,
				OverallGrade: analyzer.MainCharacterEnergy,
			},
			Chain: analyzer.ChainAnalysis{
				ChainLength:       2,
				ChainOrderCorrect: true,
				OverallGrade:      analyzer.WrittenInCrayon,
				Certificates: []analyzer.CertAnalysis{
					{
						Depth:          0,
						Role:           analyzer.RoleLeaf,
						CommonName:     "legacy.corp.local",
						DaysRemaining:  90,
						ValidityDays:   730, // > 398 days to test internalCA interaction
						ExpiryGrade:    analyzer.MainCharacterEnergy,
						SignatureGrade: analyzer.MainCharacterEnergy,
						KeyGrade:       analyzer.MainCharacterEnergy,
						HostnameMatch:  false,
						MissingSANs:    true,
						CNOnlyMatch:    true,
						OverallGrade:   analyzer.WrittenInCrayon,
					},
				},
			},
			InternalCAMode: internalCA,
		}

		warnings := BuildWarnings(report, internalCA)
		warnings = SuppressPublicCAOnlyWarnings(warnings)

		var foundMissingSAN, foundGenericMismatch bool
		for _, w := range warnings {
			if w.Code == "CERT_MISSING_SANS" {
				foundMissingSAN = true
				if w.Severity != analyzer.WrittenInCrayon {
					t.Errorf("CERT_MISSING_SANS severity = %v, want WrittenInCrayon", w.Severity)
				}
				if !sayingsSet[w.Why] {
					t.Errorf("CERT_MISSING_SANS Why %q did not come from MissingSANSayings", w.Why)
				}
			}
			if w.Code == "CERT_HOSTNAME_MISMATCH" {
				foundGenericMismatch = true
			}
		}

		if !foundMissingSAN {
			t.Fatalf("internalCA=%v: expected CERT_MISSING_SANS warning, got %+v", internalCA, warnings)
		}
		if foundGenericMismatch {
			t.Errorf("internalCA=%v: should not emit duplicate CERT_HOSTNAME_MISMATCH alongside CERT_MISSING_SANS", internalCA)
		}

		verdicts := EvaluateDualVerdict(report.Chain.OverallGrade, warnings)
		if verdicts.BrowserVerdict != analyzer.WrittenInCrayon {
			t.Errorf("internalCA=%v: BrowserVerdict = %v, want WrittenInCrayon", internalCA, verdicts.BrowserVerdict)
		}
		if verdicts.ServiceVerdict != analyzer.WrittenInCrayon {
			t.Errorf("internalCA=%v: ServiceVerdict = %v, want WrittenInCrayon", internalCA, verdicts.ServiceVerdict)
		}
	}
}

func TestCNOnlyWarning_WhenOtherSANsExist(t *testing.T) {
	report := &analyzer.DiagnosticReport{
		Handshake: analyzer.HandshakeAnalysis{
			TLSVersion:   "TLSv1.3",
			CipherGrade:  analyzer.MainCharacterEnergy,
			VersionGrade: analyzer.MainCharacterEnergy,
			OverallGrade: analyzer.MainCharacterEnergy,
		},
		Chain: analyzer.ChainAnalysis{
			ChainLength:       2,
			ChainOrderCorrect: true,
			OverallGrade:      analyzer.WrittenInCrayon,
			Certificates: []analyzer.CertAnalysis{
				{
					Depth:          0,
					Role:           analyzer.RoleLeaf,
					CommonName:     "api.example.com",
					DNSNames:       []string{"www.example.com"},
					DaysRemaining:  90,
					ValidityDays:   90,
					ExpiryGrade:    analyzer.MainCharacterEnergy,
					SignatureGrade: analyzer.MainCharacterEnergy,
					KeyGrade:       analyzer.MainCharacterEnergy,
					HostnameMatch:  false,
					MissingSANs:    false,
					CNOnlyMatch:    true,
					OverallGrade:   analyzer.WrittenInCrayon,
				},
			},
		},
	}

	warnings := BuildWarnings(report, false)
	var foundCNOnly bool
	for _, w := range warnings {
		if w.Code == "CERT_CN_ONLY" {
			foundCNOnly = true
			if w.Severity != analyzer.WrittenInCrayon {
				t.Errorf("CERT_CN_ONLY severity = %v, want WrittenInCrayon", w.Severity)
			}
		}
	}
	if !foundCNOnly {
		t.Fatalf("expected CERT_CN_ONLY warning, got %+v", warnings)
	}
}
