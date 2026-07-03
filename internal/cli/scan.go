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
  - SSL/TLS version probing (SSLv3, TLS 1.0–1.3)

CRL checks iterate all distribution points. LDAP endpoints (common with
Microsoft AD CS) are detected and skipped — HTTP endpoints are tried instead.
If an HTTPS CRL endpoint has a TLS error, peep retries with TLS verification
disabled and warns you (the CRL data is signature-verified against the CA).

CT checks parse Signed Certificate Timestamps (SCTs) embedded directly in
the certificate — no external API calls needed. SCTs are cryptographic proof
that the certificate was submitted to CT logs before issuance.
Certificates from private/internal CAs are automatically skipped.

Use --explain (--whytho) to add detailed explanations, recommended fixes,
and documentation references for every finding. Works on all peep commands.

Examples:
  peep scan example.com
  peep scan --explain example.com
  peep scan --whytho internal-server.local
  peep scan --examples          Show detailed scan examples with jq queries`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	if showExamples(cmd.Name()) {
		return nil
	}

	if len(args) == 0 {
		return cmd.Help()
	}

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

	if !flagJSON {
		fmt.Println(ui.Theme.MutedStyle.Render("  Starting deep scan..."))
		fmt.Println()
	}

	startTime := time.Now()

	result, err := probe.Probe(probe.ProbeOptions{
		Host:    host,
		Port:    port,
		Timeout: timeout,
		Proto:   flagProto,
	})
	if err != nil {
		if flagJSON {
			fmt.Printf(`{"error": %q}`, err.Error())
			fmt.Println()
		} else {
			fmt.Println(ui.Theme.ErrorStyle.Render(fmt.Sprintf("\n[FAIL] Failed to connect: %s", err)))
		}
		return nil
	}

	// JSON mode: collect all results silently, output as JSON
	if flagJSON {
		return runScanJSON(cmd, result, host, port, timeout, startTime)
	}

	fmt.Println(ui.RenderBanner(result.Host, result.Port, result.IP, result.Protocol))

	handshake := analyzer.AnalyzeHandshake(result.ConnState)
	chain := analyzer.AnalyzeChain(result.ConnState, host, flagInsecure, flagCABundle)

	// Build a diagnostic report for warning generation
	report := &analyzer.DiagnosticReport{
		Target: analyzer.TargetInfo{
			Host:     result.Host,
			Port:     result.Port,
			IP:       result.IP,
			Protocol: result.Protocol,
		},
		Handshake: handshake,
		Chain:     chain,
	}

	// Collect all warnings from the education package
	var allWarnings []analyzer.Warning
	allWarnings = append(allWarnings, education.BuildWarnings(report, flagInternalCA)...)

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
			allWarnings = append(allWarnings, stapleWarnings...)
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

			// Collect OCSP live warnings
			ocspWarnings := education.CheckOCSPLiveWarnings(ocspResult)
			allWarnings = append(allWarnings, ocspWarnings...)
			for _, w := range ocspWarnings {
				if w.Severity > chain.OverallGrade {
					chain.OverallGrade = w.Severity
				}
			}
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
			allWarnings = append(allWarnings, crlWarnings...)
			for _, w := range crlWarnings {
				if w.Severity > chain.OverallGrade {
					chain.OverallGrade = w.Severity
				}
			}
		}

		// CT log check (SCT parsing — no network call)
		fmt.Println(ui.Theme.MutedStyle.Render("  Checking Certificate Transparency (embedded SCTs)..."))
		ctResult := analyzer.CheckCTLogs(leaf.RawCert, chain.TrustStoreVerified)
		fmt.Println(ui.RenderCTLogResult(ctResult, flagInternalCA))

		// Collect CT warnings
		ctWarnings := education.CheckCTWarnings(ctResult, flagInternalCA)
		allWarnings = append(allWarnings, ctWarnings...)
		for _, w := range ctWarnings {
			if w.Severity > chain.OverallGrade {
				chain.OverallGrade = w.Severity
			}
		}

		// CA origin assessment (standard mode only — skip when --internal-ca is set)
		if !flagInternalCA {
			caOrigin := analyzer.DetectCAOrigin(chain, leaf.RawCert, ctResult.Found)
			if caOrigin.Assessment != "public_ca" {
				fmt.Println(ui.RenderCAOriginEvidence(caOrigin))
			}
		}
	}

	// Cipher suite enumeration
	fmt.Println(ui.Theme.MutedStyle.Render("  Enumerating supported cipher suites (this may take a moment)..."))
	cipherResult := analyzer.EnumerateCiphers(host, port, timeout)
	fmt.Println(ui.RenderCipherEnum(cipherResult))

	// Collect cipher and TLS version probe warnings
	allWarnings = append(allWarnings, education.CheckCipherEnumWarnings(cipherResult)...)
	allWarnings = append(allWarnings, education.CheckTLSVersionProbeWarnings(cipherResult)...)

	// Cert cards (always shown in scan, or gated by -d if you prefer)
	for _, cert := range chain.Certificates {
		fmt.Println(ui.RenderCertCard(cert))
	}

	// -r / --raw: Show raw x509 text output
	if flagRaw {
		renderRawX509(chain)
	}

	// FINDINGS section — render collected warnings
	if len(allWarnings) > 0 && (flagDetails || flagExplain) {
		fmt.Println(ui.RenderWarnings(allWarnings, flagExplain))
	}

	// Overall
	overallStatus := chain.OverallGrade
	if handshake.OverallGrade > overallStatus {
		overallStatus = handshake.OverallGrade
	}
	for _, w := range allWarnings {
		if w.Severity > overallStatus {
			overallStatus = w.Severity
		}
	}

	// Scan duration
	duration := fmt.Sprintf("  Scan completed in %s", time.Since(startTime).Round(time.Millisecond))
	if flagExplain {
		duration += ui.Theme.MutedStyle.Render(fmt.Sprintf(" — %s", ui.RandomScanComment()))
	}
	fmt.Println(ui.Theme.MutedStyle.Render(duration))
	fmt.Println()

	fmt.Println(ui.RenderOverallStatus(overallStatus))

	// Save certs if requested
	if isSaveRequested(cmd) {
		if err := saveCerts(chain, host, flagSave); err != nil {
			fmt.Println(ui.Theme.ErrorStyle.Render(fmt.Sprintf("\n[FAIL] Save error: %s", err)))
		}
	}

	return nil
}

func runScanJSON(cmd *cobra.Command, result *probe.ProbeResult, host, port string, timeout time.Duration, startTime time.Time) error {
	handshake := analyzer.AnalyzeHandshake(result.ConnState)
	chain := analyzer.AnalyzeChain(result.ConnState, host, flagInsecure, flagCABundle)

	report := analyzer.ScanReport{
		Target: analyzer.TargetInfo{
			Host:     result.Host,
			Port:     result.Port,
			IP:       result.IP,
			Protocol: result.Protocol,
		},
		Handshake: handshake,
		Chain:     chain,
		Timestamp: time.Now(),
	}

	// Collect warnings from education package
	diagReport := &analyzer.DiagnosticReport{
		Handshake: handshake,
		Chain:     chain,
	}
	var allWarnings []analyzer.Warning
	allWarnings = append(allWarnings, education.BuildWarnings(diagReport, flagInternalCA)...)

	// OCSP Staple
	if len(result.ConnState.PeerCertificates) >= 2 {
		stapleResult := analyzer.CheckOCSPStaple(result.ConnState, result.ConnState.PeerCertificates[1])
		report.OCSPStaple = &stapleResult
		allWarnings = append(allWarnings, education.CheckOCSPStapleWarnings(stapleResult)...)
	}

	// OCSP Live
	if len(result.ConnState.PeerCertificates) >= 2 {
		ocspResult := analyzer.CheckOCSP(result.ConnState.PeerCertificates[0], result.ConnState.PeerCertificates[1], timeout)
		report.OCSP = &ocspResult
		allWarnings = append(allWarnings, education.CheckOCSPLiveWarnings(ocspResult)...)
	}

	// CRL
	if len(result.ConnState.PeerCertificates) >= 2 {
		crlResult := analyzer.CheckCRL(result.ConnState.PeerCertificates[0], result.ConnState.PeerCertificates[1], timeout)
		report.CRL = &crlResult
		allWarnings = append(allWarnings, education.CheckCRLWarnings(crlResult)...)
	}

	// CT
	if len(chain.Certificates) > 0 {
		leaf := chain.Certificates[0]
		ctResult := analyzer.CheckCTLogs(leaf.RawCert, chain.TrustStoreVerified)
		report.CT = &ctResult
		allWarnings = append(allWarnings, education.CheckCTWarnings(ctResult, flagInternalCA)...)

		// CA Origin
		if !flagInternalCA {
			caOrigin := analyzer.DetectCAOrigin(chain, leaf.RawCert, ctResult.Found)
			report.CAOrigin = &caOrigin
		}
	}

	// Ciphers
	cipherResult := analyzer.EnumerateCiphers(host, port, timeout)
	report.Ciphers = &cipherResult
	allWarnings = append(allWarnings, education.CheckCipherEnumWarnings(cipherResult)...)
	allWarnings = append(allWarnings, education.CheckTLSVersionProbeWarnings(cipherResult)...)

	// Calculate overall grade
	overallStatus := chain.OverallGrade
	if handshake.OverallGrade > overallStatus {
		overallStatus = handshake.OverallGrade
	}
	for _, w := range allWarnings {
		if w.Severity > overallStatus {
			overallStatus = w.Severity
		}
	}

	// Strip explain/fix unless --explain
	if !flagExplain {
		stripped := make([]analyzer.Warning, len(allWarnings))
		for i, w := range allWarnings {
			stripped[i] = analyzer.Warning{
				Code:     w.Code,
				Severity: w.Severity,
				Title:    w.Title,
				Detail:   w.Detail,
			}
		}
		allWarnings = stripped
	}
	// Sanitize all warning string fields for clean JSON output
	allWarnings = sanitizeWarnings(allWarnings)

	report.Warnings = allWarnings
	report.OverallStatus = overallStatus
	report.ScanDurationMs = time.Since(startTime).Milliseconds()

	data, err := marshalCleanJSON(report)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Println(string(data))
	return nil
}

