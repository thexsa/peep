package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/thexsa/peep/internal/analyzer"
	"github.com/thexsa/peep/internal/education"
)

func TestRenderMissingSANsInCertCardAndChainDiagram(t *testing.T) {
	ResetSass()
	now := time.Now()

	leaf := analyzer.CertAnalysis{
		Depth:          0,
		Role:           analyzer.RoleLeaf,
		Subject:        "CN=legacy.corp.local",
		Issuer:         "CN=Corp Issuing CA",
		CommonName:     "legacy.corp.local",
		NotBefore:      now.Add(-24 * time.Hour),
		NotAfter:       now.Add(90 * 24 * time.Hour),
		DaysRemaining:  90,
		ExpiryGrade:    analyzer.MainCharacterEnergy,
		KeyType:        "ECDSA P-256",
		KeyBits:        256,
		KeyGrade:       analyzer.MainCharacterEnergy,
		SignatureAlg:   "ECDSA-SHA256",
		SignatureGrade: analyzer.MainCharacterEnergy,
		SerialNumber:   "01AB",
		Fingerprint:    "DEADBEEF",
		HostnameMatch:  false,
		MissingSANs:    true,
		CNOnlyMatch:    true,
		OverallGrade:   analyzer.WrittenInCrayon,
	}

	card := RenderCertCard(leaf)
	if !strings.Contains(card, "missing Subject Alternative Name extension") {
		t.Errorf("RenderCertCard did not highlight missing SAN extension:\n%s", card)
	}
	if !strings.Contains(card, "relies on deprecated Common Name") {
		t.Errorf("RenderCertCard did not highlight CN-only fallback:\n%s", card)
	}

	chain := analyzer.ChainAnalysis{
		Certificates:      []analyzer.CertAnalysis{leaf},
		ChainLength:       1,
		ChainOrderCorrect: true,
		OverallGrade:      analyzer.WrittenInCrayon,
	}
	diagram := RenderChainDiagram(chain, 0)
	if !strings.Contains(diagram, "NONE (missing SAN extension!)") {
		t.Errorf("RenderChainDiagram did not display Covers: NONE:\n%s", diagram)
	}
	if !strings.Contains(diagram, "Leaf certificate has NO SANs (CN-only fallback)") {
		t.Errorf("RenderChainDiagram did not display missing-SAN chain callout:\n%s", diagram)
	}

	// Verify at least one of the MissingSANSayings words/phrases was rendered
	foundRemark := false
	for _, remark := range education.MissingSANSayings {
		// Check first 24 chars of remark (before line wrapping splits it)
		prefix := remark
		if len(prefix) > 24 {
			prefix = prefix[:24]
		}
		if strings.Contains(diagram, prefix) {
			foundRemark = true
			break
		}
	}
	if !foundRemark {
		t.Errorf("expected RenderChainDiagram to include a remark from education.MissingSANSayings:\n%s", diagram)
	}
}
