package ui

import (
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/thexsa/peep/internal/analyzer"
	"github.com/thexsa/peep/internal/education"
)

func assertStrict7BitASCIIAndNoEmoji(t *testing.T, label, s string) {
	t.Helper()

	if strings.Contains(s, "\x1b") {
		t.Errorf("%s contains ANSI escape code in plain-text mode: %q", label, s)
	}

	for idx, r := range s {
		if r == '\n' || r == '\t' || (r >= 0x20 && r <= 0x7E) {
			continue
		}
		t.Errorf("%s contains non-7-bit-ASCII rune U+%04X (%q) at byte %d in plain-text mode",
			label, r, string(r), idx)
	}

	// Extra belt-and-suspenders check: no Unicode Symbol/Other/So/Variation-Selector runes
	for _, r := range s {
		if r > unicode.MaxASCII {
			t.Errorf("%s leaked non-ASCII rune U+%04X", label, r)
		}
	}
}

func TestPlainTextMappingsAndZeroEmojiHardRule(t *testing.T) {
	// Snapshot and restore package-level theme state so other tests in package ui are unaffected.
	origPlain := PlainTextMode
	origTheme := Theme
	origCard := CardBorder
	origSection := SectionBorder
	origHeader := HeaderBorder
	defer func() {
		PlainTextMode = origPlain
		Theme = origTheme
		CardBorder = origCard
		SectionBorder = origSection
		HeaderBorder = origHeader
	}()

	EnablePlainText()

	t.Run("exact symbol and emoji mappings", func(t *testing.T) {
		cases := []struct {
			in   string
			want string
		}{
			{"🌐 Browser: Main Character Energy", "[Browser] Browser: Main Character Energy"},
			{"🤖 Service/API: Mall Cop Credentials", "[Service] Service/API: Mall Cop Credentials"},
			{"👉 CHAIN_WRONG_ORDER", "-> CHAIN_WRONG_ORDER"},
			{"✓ Full chain → out.pem", "[OK] Full chain -> out.pem"},
			{"✗ Failed — bad cert…", "[FAIL] Failed -- bad cert..."},
			{"📸 POLAROID SAVED 💪 🎉", "POLAROID SAVED"},
		}
		for _, tc := range cases {
			got := StripEmoji(tc.in)
			if got != tc.want {
				t.Errorf("StripEmoji(%q) = %q, want %q", tc.in, got, tc.want)
			}
			assertStrict7BitASCIIAndNoEmoji(t, tc.in, got)
		}
	})

	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	sampleLeaf := analyzer.CertAnalysis{
		Depth:         0,
		Role:          analyzer.RoleLeaf,
		Subject:       "CN=legacy.corp.local",
		Issuer:        "CN=Corp Issuing CA",
		CommonName:    "legacy.corp.local",
		Organization:  "Example Corp",
		NotBefore:     now.Add(-30 * 24 * time.Hour),
		NotAfter:      now.Add(60 * 24 * time.Hour),
		DaysRemaining: 60,
		SerialNumber:  "01:AB:CD:EF",
		SignatureAlg:  "SHA256-RSA",
		KeyType:       "RSA",
		KeyBits:       2048,
		Fingerprint:   "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
		MissingSANs:   true,
		CNOnlyMatch:   true,
		OverallGrade:  analyzer.WrittenInCrayon,
	}
	sampleChain := analyzer.ChainAnalysis{
		Certificates:                []analyzer.CertAnalysis{sampleLeaf},
		ChainLength:                 1,
		HasMissingIntermediate:      true,
		LeafOnlyMissingIntermediate: true,
		NoIssuingCAInResponse:       true,
		HasUnnecessaryRoot:          true,
		ChainOrderCorrect:           false,
		TrustStoreVerified:          false,
		VerificationError:           "x509: certificate signed by unknown authority",
		SystemCAStorePath:           "Windows Certificate Store (Cert:\\LocalMachine\\Root)",
		OverallGrade:                analyzer.WrittenInCrayon,
	}
	sampleWarnings := []analyzer.Warning{
		{
			Code:     "CERT_MISSING_SANS",
			Severity: analyzer.WrittenInCrayon,
			Title:    "Certificate Has NO Subject Alternative Names (SANs)",
			Detail:   "Leaf cert has zero DNS/IP SANs — relies on Common Name.",
			Why:      PickSass(education.MissingSANSayings),
			Explain:  "Modern browsers — Chrome, Edge, Firefox, Safari — require SANs.",
			Fix:      "Re-issue with subjectAltName = DNS:legacy.corp.local",
			DocRef:   "certs",
		},
	}

	divergentVerdict := analyzer.DualVerdict{
		BrowserVerdict: analyzer.MainCharacterEnergy,
		ServiceVerdict: analyzer.MallCopCredentials,
		RootCauses:     []string{"CHAIN_WRONG_ORDER", "OCSP_STAPLE_MISSING"},
	}
	unnecessaryRootVerdict := analyzer.DualVerdict{
		BrowserVerdict: analyzer.MainCharacterEnergy,
		ServiceVerdict: analyzer.MallCopCredentials,
		RootCauses:     []string{"CHAIN_UNNECESSARY_ROOT"},
	}
	matchingFailVerdict := analyzer.DualVerdict{
		BrowserVerdict: analyzer.WrittenInCrayon,
		ServiceVerdict: analyzer.WrittenInCrayon,
		RootCauses:     []string{"CERT_MISSING_SANS"},
	}

	report := &analyzer.DiagnosticReport{
		Target: analyzer.TargetInfo{
			Host:     "legacy.corp.local",
			Port:     "443",
			IP:       "10.0.0.15",
			Protocol: "TLS",
		},
		Handshake: analyzer.HandshakeAnalysis{
			TLSVersion:   "TLSv1.3",
			VersionGrade: analyzer.MainCharacterEnergy,
			CipherSuite:  "TLS_AES_256_GCM_SHA384",
			CipherGrade:  analyzer.MainCharacterEnergy,
			OverallGrade: analyzer.MainCharacterEnergy,
		},
		Chain:         sampleChain,
		Warnings:      sampleWarnings,
		Verdicts:      divergentVerdict,
		OverallStatus: divergentVerdict.ServiceVerdict,
	}

	outputs := map[string]string{
		"RenderBanner":                RenderBanner("legacy.corp.local", "443", "10.0.0.15", "TLS"),
		"RenderSummaryHeader_Diverge": RenderSummaryHeader("legacy.corp.local", "443", "10.0.0.15", "TLS", report),
		"RenderDualVerdict_Diverge":   RenderDualVerdict(divergentVerdict),
		"RenderDualVerdict_UnnecRoot": RenderDualVerdict(unnecessaryRootVerdict),
		"RenderDualVerdict_Match":     RenderDualVerdict(matchingFailVerdict),
		"RenderCertCard":              RenderCertCard(sampleLeaf),
		"RenderChainDiagram":          RenderChainDiagram(sampleChain, 2),
		"RenderHandshakeCard":         RenderHandshakeCard(report.Handshake),
		"RenderWarnings_Explain":      RenderWarnings(sampleWarnings, true),
		"RenderVersion":               RenderVersion("0.8.0", "github-release", "windows/arm64"),
		"RenderUpdateNotification":    RenderUpdateNotification("0.7.0", "0.8.0"),
		"RenderOCSPResult": RenderOCSPResult(analyzer.OCSPResult{
			Status:       analyzer.OCSPGood,
			ResponderURL: "http://ocsp.example.com",
			ThisUpdate:   now.Add(-time.Hour),
			NextUpdate:   now.Add(time.Hour),
		}),
		"RenderOCSPStapleResult": RenderOCSPStapleResult(analyzer.OCSPStapleResult{
			Present:       false,
			HasMustStaple: true,
		}),
		"RenderCRLResult_LDAP": RenderCRLResult(analyzer.CRLResult{
			Available:    true,
			IsLDAP:       true,
			LDAPEndpoint: "ldap:///CN=CorpCA,CN=AIA,DC=corp,DC=local?certificateRevocationList",
		}),
		"RenderCTLogResult": func() string {
			ctRes := analyzer.CTLogResult{Found: true}
			sctSlice := reflect.MakeSlice(reflect.TypeOf(ctRes.SCTs), 1, 1)
			sctSlice.Index(0).FieldByName("LogID").SetString("0123456789abcdef0123456789abcdef")
			sctSlice.Index(0).FieldByName("Timestamp").Set(reflect.ValueOf(now))
			reflect.ValueOf(&ctRes.SCTs).Elem().Set(sctSlice)
			return RenderCTLogResult(ctRes, false)
		}(),
		"RenderCAOriginEvidence": RenderCAOriginEvidence(analyzer.DetectCAOrigin(sampleChain, nil, false)),
		"RenderCipherEnum": RenderCipherEnum(analyzer.CipherEnumResult{
			TLSVersions: []analyzer.TLSVersionSupport{
				{Version: "TLSv1.3", Supported: true, Grade: analyzer.MainCharacterEnergy},
				{Version: "TLSv1.0", Supported: true, Grade: analyzer.WrittenInCrayon},
			},
			SupportedSuites: []analyzer.CipherSuiteInfo{
				{Name: "TLS_AES_256_GCM_SHA384", Version: "TLSv1.3", Grade: analyzer.MainCharacterEnergy},
				{Name: "TLS_RSA_WITH_RC4_128_SHA", Version: "TLSv1.0", Grade: analyzer.WrittenInCrayon},
			},
		}),
	}

	for name, out := range outputs {
		assertStrict7BitASCIIAndNoEmoji(t, name, out)
	}

	// Verify divergent verdict explicitly contains ASCII tags [Browser], [Service], and ->
	divOut := outputs["RenderDualVerdict_Diverge"]
	for _, token := range []string{"[Browser]", "[Service]", "-> CHAIN_WRONG_ORDER"} {
		if !strings.Contains(divOut, token) {
			t.Errorf("RenderDualVerdict plain-text output missing %q:\n%s", token, divOut)
		}
	}

	// Verify built-in docs TableOfContents and every topic render cleanly to 7-bit ASCII
	assertStrict7BitASCIIAndNoEmoji(t, "docs.TableOfContents", StripEmoji(education.TableOfContents()))
	for _, topic := range education.GetTopics() {
		assertStrict7BitASCIIAndNoEmoji(t, "docs."+topic.Name, StripEmoji(topic.Content))
	}
}
