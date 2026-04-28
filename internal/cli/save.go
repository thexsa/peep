package cli

import (
	"encoding/pem"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/thexsa/peep/internal/analyzer"
	"github.com/thexsa/peep/internal/ui"
)

// saveCerts saves cert PEM files from the chain.
// If saveIndex is empty or "all", save the full chain as a single PEM.
// If saveIndex is a number, save only that specific cert by chain index.
func saveCerts(chain analyzer.ChainAnalysis, host string, saveIndex string) error {
	if len(chain.Certificates) == 0 {
		return fmt.Errorf("no certificates in chain to save")
	}

	// Sanitize hostname for filenames
	safeHost := sanitizeHostname(host)

	saveIndex = strings.TrimSpace(saveIndex)

	// Determine whether to save all or a specific index
	if saveIndex == "" || strings.EqualFold(saveIndex, "all") {
		return saveFullChain(chain, safeHost)
	}

	// Parse as index
	idx, err := strconv.Atoi(saveIndex)
	if err != nil {
		return fmt.Errorf("invalid cert index %q — use a number (0, 1, 2...) or omit for all", saveIndex)
	}

	if idx < 0 || idx >= len(chain.Certificates) {
		return fmt.Errorf("cert index %d is out of range — chain has %d cert(s) (0–%d)",
			idx, len(chain.Certificates), len(chain.Certificates)-1)
	}

	return saveSingleCert(chain.Certificates[idx], safeHost, idx)
}

// saveFullChain saves all certs as a single fullchain PEM file.
func saveFullChain(chain analyzer.ChainAnalysis, safeHost string) error {
	fmt.Println()
	var fullChainPEM []byte

	for _, cert := range chain.Certificates {
		fullChainPEM = append(fullChainPEM, encodeCertPEM(cert)...)
	}

	fullchainFile := fmt.Sprintf("%s_fullchain.pem", safeHost)
	if err := os.WriteFile(fullchainFile, fullChainPEM, 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", fullchainFile, err)
	}

	// Render summary
	var lines []string
	lines = append(lines, ui.Theme.BoldStyle.Render("📸 POLAROID SAVED"))
	lines = append(lines, "")

	// List what's in the chain
	for i, cert := range chain.Certificates {
		name := cert.CommonName
		if name == "" {
			name = cert.Subject
		}
		lines = append(lines, fmt.Sprintf("  %s [%d] %s (%s)",
			ui.Theme.SuccessStyle.Render("✓"),
			i, name, cert.Role))
	}
	lines = append(lines, "")
	lines = append(lines, fmt.Sprintf("  %s Full chain → %s (%d certs)",
		ui.Theme.SuccessStyle.Render("✓"),
		fullchainFile,
		len(chain.Certificates)))

	fmt.Println(ui.ApplyBorder(lines, ui.CardBorder))
	return nil
}

// saveSingleCert saves a single cert by index.
func saveSingleCert(cert analyzer.CertAnalysis, safeHost string, idx int) error {
	fmt.Println()
	pemData := encodeCertPEM(cert)

	filename := certFilename(safeHost, idx, cert.Role)
	if err := os.WriteFile(filename, pemData, 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", filename, err)
	}

	name := cert.CommonName
	if name == "" {
		name = cert.Subject
	}

	var lines []string
	lines = append(lines, ui.Theme.BoldStyle.Render("📸 POLAROID SAVED"))
	lines = append(lines, "")
	lines = append(lines, fmt.Sprintf("  %s [%d] %s → %s (%s)",
		ui.Theme.SuccessStyle.Render("✓"),
		idx, name, filename, cert.Role))

	fmt.Println(ui.ApplyBorder(lines, ui.CardBorder))
	return nil
}

// encodeCertPEM encodes a CertAnalysis's raw cert as PEM.
func encodeCertPEM(cert analyzer.CertAnalysis) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.RawCert.Raw,
	})
}

// certFilename generates a descriptive PEM filename.
// Format: <host>_<depth>_<role>.pem
func certFilename(safeHost string, depth int, role analyzer.CertRole) string {
	roleStr := strings.ToLower(role.String())
	roleStr = strings.ReplaceAll(roleStr, " ", "_")
	return fmt.Sprintf("%s_%d_%s.pem", safeHost, depth, roleStr)
}

// sanitizeHostname replaces characters that are invalid in filenames.
func sanitizeHostname(host string) string {
	replacer := strings.NewReplacer(
		":", "_",
		"/", "_",
		"\\", "_",
		"*", "_",
		"?", "_",
		"\"", "_",
		"<", "_",
		">", "_",
		"|", "_",
	)
	return replacer.Replace(host)
}
