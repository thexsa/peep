package cli

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/thexsa/peep/internal/analyzer"
	"github.com/thexsa/peep/internal/education"
	"github.com/thexsa/peep/internal/probe"
	"github.com/thexsa/peep/internal/ui"
)

var scanCmd = &cobra.Command{
	Use:   "scan <host>[:<port>]",
	Short: "Deep scan — cipher enumeration, OCSP, CRL, and CT log checks",
	Long: `Perform a deep scan including:

  - All checks from the default 'peep' command
  - OCSP staple check (did the server staple an OCSP response?)
  - OCSP revocation check (live query to the CA's OCSP responder)
  - CRL revocation check (fetch and parse the Certificate Revocation List)
  - Certificate Transparency verification (parse embedded SCTs)
  - Cipher suite enumeration (which ciphers does the server support?)
  - TLS version probing (which versions are enabled?)

Note: This scan takes longer due to multiple connection probes.

CT checks parse Signed Certificate Timestamps (SCTs) embedded directly in
the certificate — no external API calls needed. SCTs are cryptographic proof
that the certificate was submitted to CT logs before issuance.
Certificates from private/internal CAs are automatically skipped.

Examples:
  peep scan example.com
  peep scan --explain example.com`,
	Args: cobra.ExactArgs(1),
	RunE: runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	if flagPlainText {
		ui.EnablePlainText()
	}

	ui.ResetSass()

	target := args[0]

	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimSuffix(target, "/")

	host, port, err := net.SplitHostPort(target)
	if err != nil {
		host = target
		port = "443"
	}

	timeout := time.Duration(flagTimeout) * time.Second

	fmt.Println(ui.Theme.MutedStyle.Render("  Starting deep scan..."))
	fmt.Println()

	result, err := probe.Probe(probe.ProbeOptions{
		Host:    host,
		Port:    port,
		Timeout: timeout,
		Proto:   flagProto,
	})
	if err != nil {
		fmt.Println(ui.Theme.ErrorStyle.Render(fmt.Sprintf("\n[FAIL] Failed to connect: %s", err)))
		return nil
	}

	fmt.Println(ui.RenderBanner(result.Host, result.Port, result.IP, result.Protocol))

	handshake := analyzer.AnalyzeHandshake(result.ConnState)
	chain := analyzer.AnalyzeChain(result.ConnState, host, flagInsecure)

	// Handshake
	fmt.Println(ui.RenderHandshakeCard(handshake))

	// Chain diagram
	fmt.Println(ui.RenderChainDiagram(chain, verbosityLevel()))

	// Revocation checks
	if len(chain.Certificates) > 0 {
		leaf := chain.Certificates[0]

		// OCSP Staple check (uses the TLS connection state)
		if len(result.ConnState.PeerCertificates) >= 2 {
			fmt.Println(ui.Theme.MutedStyle.Render("  Checking stapled OCSP response..."))
			stapleResult := analyzer.CheckOCSPStaple(result.ConnState, result.ConnState.PeerCertificates[1])
			fmt.Println(ui.RenderOCSPStapleResult(stapleResult))

			// Collect OCSP staple warnings
			stapleWarnings := education.CheckOCSPStapleWarnings(stapleResult)
			for _, w := range stapleWarnings {
				if w.Severity > chain.OverallGrade {
					chain.OverallGrade = w.Severity
				}
			}
		}

		// Active OCSP check
		fmt.Println(ui.Theme.MutedStyle.Render("  Checking OCSP revocation status..."))
		if len(result.ConnState.PeerCertificates) >= 2 {
			ocspResult := analyzer.CheckOCSP(
				result.ConnState.PeerCertificates[0],
				result.ConnState.PeerCertificates[1],
				timeout,
			)
			fmt.Println(ui.RenderOCSPResult(ocspResult))
		} else if leaf.IsSelfSigned {
			fmt.Println(ui.Theme.MutedStyle.Render("  Skipping OCSP — self-signed cert"))
			fmt.Println()
		} else {
			fmt.Println(ui.Theme.MutedStyle.Render("  Skipping OCSP — no issuer cert available"))
			fmt.Println()
		}

		// CRL check
		if len(result.ConnState.PeerCertificates) >= 2 {
			fmt.Println(ui.Theme.MutedStyle.Render("  Checking CRL revocation status..."))
			crlResult := analyzer.CheckCRL(
				result.ConnState.PeerCertificates[0],
				result.ConnState.PeerCertificates[1],
				timeout,
			)
			fmt.Println(ui.RenderCRLResult(crlResult))

			// Collect CRL warnings
			crlWarnings := education.CheckCRLWarnings(crlResult)
			for _, w := range crlWarnings {
				if w.Severity > chain.OverallGrade {
					chain.OverallGrade = w.Severity
				}
			}
		}

		// CT log check (SCT parsing — no network call)
		fmt.Println(ui.Theme.MutedStyle.Render("  Checking Certificate Transparency (embedded SCTs)..."))
		ctResult := analyzer.CheckCTLogs(leaf.RawCert, chain.TrustStoreVerified)
		fmt.Println(ui.RenderCTLogResult(ctResult))
	}

	// Cipher suite enumeration
	fmt.Println(ui.Theme.MutedStyle.Render("  Enumerating supported cipher suites (this may take a moment)..."))
	cipherResult := analyzer.EnumerateCiphers(host, port, timeout)
	fmt.Println(ui.RenderCipherEnum(cipherResult))

	// Cert cards (always shown in scan, or gated by -d if you prefer)
	for _, cert := range chain.Certificates {
		fmt.Println(ui.RenderCertCard(cert))
	}

	// -r / --raw / --ogle: Show raw x509 text output
	if flagRaw {
		renderRawX509(chain)
	}

	// Overall
	overallStatus := chain.OverallGrade
	if handshake.OverallGrade > overallStatus {
		overallStatus = handshake.OverallGrade
	}
	fmt.Println(ui.RenderOverallStatus(overallStatus))

	// Save certs if requested
	if isSaveRequested(cmd) {
		if err := saveCerts(chain, host, flagSave); err != nil {
			fmt.Println(ui.Theme.ErrorStyle.Render(fmt.Sprintf("\n[FAIL] Save error: %s", err)))
		}
	}

	return nil
}

