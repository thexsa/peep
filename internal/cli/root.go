package cli

import (
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/thexsa/peep/internal/analyzer"
	"github.com/thexsa/peep/internal/education"
	"github.com/thexsa/peep/internal/probe"
	"github.com/thexsa/peep/internal/ui"
	"github.com/thexsa/peep/internal/updater"
)

var (
	// Flags
	flagProto      string
	flagTimeout    int
	flagJSON       bool
	flagPlainText  bool
	flagInsecure   bool
	flagVerbose    bool   // -v/--verbose/--stare: PEM certs (was -vv)
	flagDetails    bool   // -d/--details/--gaze: cert detail cards (was -v)
	flagExplain    bool   // -e/--explain/--whytho
	flagSave       string // -s/--save/--polaroid: "all" or index number
	flagSaveSet    bool   // tracks whether --save was explicitly set
	flagRaw        bool   // -r/--raw/--ogle: raw x509 text output
	flagInternalCA bool   // --internal-ca: adjust grading for internal/private CA certs
	flagCABundle   string // --ca-bundle: path to custom CA bundle (replaces system trust store)
	flagConnCheck  bool   // -c/--connect/--knock: TCP connectivity check only
)

var rootCmd = &cobra.Command{
	Use:   "peep <host>[:<port>]",
	Short: "peep — your digital eyes for TLS diagnostics",
	Long: `peep is a TLS diagnostic tool for support engineers, SREs, platform
folks, and anyone who is tired of pretending hex dumps are a personality.
It peeps into TLS handshakes & certificate chains, & tells you what's
broken in plain English, instead of cryptographic cave paintings — because
"PKIX path building failed" was not helpful.

Smart protocol detection: peep handles HTTPS, SMTP, RDP, LDAP,
FTP, POP3, IMAP, MSSQL, MySQL, PostgreSQL, XMPP, and more.
Just give it a host and port.

Examples:
  peep example.com              Quick check on port 443
  peep example.com:8443         Check a specific port
  peep -c server:3389           TCP connectivity check (like telnet/nc)
  peep -d example.com           Cert detail cards
  peep -v example.com           Full details + base64 PEM certs
  peep --whytho example.com     Explain issues with fixes & doc refs
  peep scan example.com         Deep scan with cipher enumeration
  peep portscan example.com     TCP port scan (top 50 ports)
  peep find-certs example.com   Discover TLS certificates across ports
  peep -P smtp server:2525      Force SMTP protocol on non-standard port
  peep --save example.com       Save all cert PEMs to files
  peep --save 0 example.com     Save just the leaf cert PEM
  peep --raw example.com        Raw x509 output for each cert
  peep docs                     Browse the built-in TLS reference guide
  peep docs --search java       Search docs for a keyword
  peep docs --all               Show all docs at once (man-page style)
  peep docs crl --json          Output a doc topic as JSON

Use --examples on any command for detailed usage examples with jq queries:
  peep --examples               Show examples for the root command
  peep scan --examples          Show examples for deep scans
  peep portscan --examples      Show port scan examples
  peep find-certs --examples    Show cert discovery examples
  peep docs --examples          Show examples for the docs browser`,
	Args: cobra.MaximumNArgs(1),
	RunE: runPeep,
}

func init() {
	// -P / --proto / --lens
	rootCmd.PersistentFlags().StringVarP(&flagProto, "proto", "P", "", "Force protocol: tls, smtp, rdp, ldap, ftp, pop3, imap, mssql, mysql, postgres, xmpp (alias: --lens)")
	rootCmd.PersistentFlags().StringVar(&flagProto, "lens", "", "Force protocol (alias for --proto)")

	// -t / --timeout / --blink
	rootCmd.PersistentFlags().IntVarP(&flagTimeout, "timeout", "t", 5, "Connection timeout in seconds (alias: --blink)")
	rootCmd.PersistentFlags().IntVar(&flagTimeout, "blink", 5, "Connection timeout in seconds (alias for --timeout)")

	// -j / --json
	rootCmd.PersistentFlags().BoolVarP(&flagJSON, "json", "j", false, "Output as JSON (for scripting)")

	// -p / --plain-text / --shades
	rootCmd.PersistentFlags().BoolVarP(&flagPlainText, "plain-text", "p", false, "Plain text output — no color, no emoji (alias: --shades)")
	rootCmd.PersistentFlags().BoolVar(&flagPlainText, "shades", false, "Plain text output (alias for --plain-text)")

	// -i / --insecure / --blindfold
	rootCmd.PersistentFlags().BoolVarP(&flagInsecure, "insecure", "i", false, "Skip system trust store verification (alias: --blindfold)")
	rootCmd.PersistentFlags().BoolVar(&flagInsecure, "blindfold", false, "Skip trust store verification (alias for --insecure)")

	// -v / --verbose / --stare (PEM certs + raw x509)
	rootCmd.PersistentFlags().BoolVarP(&flagVerbose, "verbose", "v", false, "Show PEM encoded certs and raw x509 output (alias: --stare)")
	rootCmd.PersistentFlags().BoolVar(&flagVerbose, "stare", false, "Show PEM + raw x509 output (alias for --verbose)")

	// -d / --details / --gaze (cert detail cards)
	rootCmd.PersistentFlags().BoolVarP(&flagDetails, "details", "d", false, "Show detailed cert info cards (alias: --gaze)")
	rootCmd.PersistentFlags().BoolVar(&flagDetails, "gaze", false, "Show detailed cert info cards (alias for --details)")

	// -e / --explain / --whytho
	rootCmd.PersistentFlags().BoolVarP(&flagExplain, "explain", "e", false, "Explain each issue with fix recommendations (alias: --whytho)")
	rootCmd.PersistentFlags().BoolVar(&flagExplain, "whytho", false, "Explain issues with fixes (alias for --explain)")

	// -s / --save / --polaroid (string: empty = all, or index number)
	rootCmd.PersistentFlags().StringVarP(&flagSave, "save", "s", "", "Save cert PEM(s) to files. No value = all, or specify index (alias: --polaroid)")
	rootCmd.PersistentFlags().Lookup("save").NoOptDefVal = "all"
	rootCmd.PersistentFlags().StringVar(&flagSave, "polaroid", "", "Save cert PEM(s) (alias for --save)")
	rootCmd.PersistentFlags().Lookup("polaroid").NoOptDefVal = "all"

	// -r / --raw
	rootCmd.PersistentFlags().BoolVarP(&flagRaw, "raw", "r", false, "Show raw x509 text output for each cert in the chain")

	// --internal-ca
	rootCmd.PersistentFlags().BoolVar(&flagInternalCA, "internal-ca", false,
		"Adjust grading for internal/private CA certificates (skips SCT and 398-day validity checks)")

	// --ca-bundle
	rootCmd.PersistentFlags().StringVar(&flagCABundle, "ca-bundle", "",
		"Path to a CA certificate bundle (.pem, .crt, .cer, .der) — replaces system trust store")

	// -c / --connect / --knock
	rootCmd.PersistentFlags().BoolVarP(&flagConnCheck, "connect", "c", false, "TCP connectivity check only — no TLS (alias: --knock)")
	rootCmd.PersistentFlags().BoolVar(&flagConnCheck, "knock", false, "TCP connectivity check (alias for --connect)")

	// --examples / --show-me
	rootCmd.PersistentFlags().BoolVar(&flagExamples, "examples", false, "Show contextual usage examples with jq queries")
	rootCmd.PersistentFlags().BoolVar(&flagExamples, "show-me", false, "Show usage examples (alias for --examples)")

	// Hide themed aliases from help — they'll be mentioned in primary flag descriptions
	for _, alias := range []string{"lens", "blink", "shades", "blindfold", "stare", "gaze", "whytho", "polaroid", "show-me", "knock"} {
		rootCmd.PersistentFlags().MarkHidden(alias)
	}
}

// Execute runs the root command.
func Execute() error {
	preprocessSaveArgs()

	// Start background update check (non-blocking)
	updateCh := startBackgroundUpdateCheck()

	err := rootCmd.Execute()

	// Print update notification after all output (skip in JSON mode)
	if !flagJSON {
		printUpdateNotification(updateCh)
	}

	return err
}

// startBackgroundUpdateCheck kicks off a goroutine that checks
// GitHub for a newer version. Returns a channel that will receive
// the result (or be closed on skip/error).
func startBackgroundUpdateCheck() <-chan *updater.UpdateInfo {
	ch := make(chan *updater.UpdateInfo, 1)

	// Skip conditions
	if Version == "dev" || Version == "" {
		close(ch)
		return ch
	}
	if os.Getenv("PEEP_NO_UPDATE_CHECK") != "" {
		close(ch)
		return ch
	}

	go func() {
		defer close(ch)

		// Check cache first — already checked recently?
		if !updater.ShouldCheck() {
			if latest, ok := updater.GetCachedResult(); ok {
				current := updater.NormalizeVersion(Version)
				if updater.IsNewer(current, latest) {
					ch <- &updater.UpdateInfo{
						CurrentVersion:  current,
						LatestVersion:   latest,
						UpdateAvailable: true,
					}
				}
			}
			return
		}

		// Not cached or stale — check GitHub
		info, err := updater.CheckForUpdate(Version)
		if err != nil {
			return // silent fail
		}

		// Save to cache regardless of result
		updater.SaveCheckResult(info.LatestVersion)

		if info.UpdateAvailable {
			ch <- info
		}
	}()

	return ch
}

// printUpdateNotification reads from the channel and prints
// a one-liner if an update is available.
func printUpdateNotification(ch <-chan *updater.UpdateInfo) {
	if ch == nil || updateJustFinished {
		return
	}

	// Non-blocking read with a short timeout so we don't delay exit
	select {
	case info, ok := <-ch:
		if ok && info != nil && info.UpdateAvailable {
			fmt.Print(ui.RenderUpdateNotification(info.CurrentVersion, info.LatestVersion))
		}
	case <-time.After(3 * time.Second):
		// Check took too long, skip notification
	}
}

// preprocessSaveArgs rewrites os.Args so that `-s 0` and `--save 2` work
// as expected. Cobra's NoOptDefVal makes the value optional, but that means
// `-s 0` treats `0` as a positional arg instead of the flag value.
// This function detects that pattern and rewrites it to `-s=0`.
func preprocessSaveArgs() {
	args := os.Args[1:]
	var newArgs []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		// Check if this is -s, --save, or --polaroid without `=` and the next arg is a number or "all"
		if (arg == "-s" || arg == "--save" || arg == "--polaroid") && i+1 < len(args) {
			next := args[i+1]
			if _, err := strconv.Atoi(next); err == nil || strings.EqualFold(next, "all") {
				newArgs = append(newArgs, arg+"="+next)
				i++ // skip the next arg, it's now part of the flag
				continue
			}
		}
		newArgs = append(newArgs, arg)
	}
	os.Args = append([]string{os.Args[0]}, newArgs...)
}

// isSaveRequested checks if --save or --polaroid was explicitly passed
// (even without a value, to distinguish from the default empty string).
func isSaveRequested(cmd *cobra.Command) bool {
	return cmd.Flags().Changed("save") || cmd.Flags().Changed("polaroid")
}

func runPeep(cmd *cobra.Command, args []string) error {
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
	host, port := parseTarget(target)

	// -c / --connect: TCP connectivity check only — no TLS
	if flagConnCheck {
		if flagPlainText {
			ui.EnablePlainText()
		}
		return runConnectivityCheck(host, port, time.Duration(flagTimeout)*time.Second)
	}

	startTime := time.Now()

	// Probe
	result, err := probe.Probe(probe.ProbeOptions{
		Host:    host,
		Port:    port,
		Timeout: time.Duration(flagTimeout) * time.Second,
		Proto:   flagProto,
	})
	if err != nil {
		if flagJSON {
			fmt.Printf(`{"error": %q}`, err.Error())
			fmt.Println()
		} else {
			fmt.Println(ui.Theme.ErrorStyle.Render(fmt.Sprintf("\n[FAIL] Failed to connect: %s", err)))
			fmt.Println(ui.Theme.MutedStyle.Render("       Maybe try checking if the server is actually running? Just a thought."))
		}
		return nil
	}

	// Analyze
	handshake := analyzer.AnalyzeHandshake(result.ConnState)
	chain := analyzer.AnalyzeChain(result.ConnState, host, flagInsecure, flagCABundle)

	// Build report
	report := &analyzer.DiagnosticReport{
		Target: analyzer.TargetInfo{
			Host:      result.Host,
			Port:      result.Port,
			IP:        result.IP,
			Protocol:  result.Protocol,
			ProbeType: result.ProbeType,
		},
		Handshake:      handshake,
		Chain:          chain,
		OverallStatus:  analyzer.MainCharacterEnergy,
		ScanDuration:   time.Since(startTime),
		Timestamp:      time.Now(),
		InternalCAMode: flagInternalCA,
	}

	// Build warnings
	report.Warnings = education.BuildWarnings(report, flagInternalCA)

	// Calculate dual verdicts (browser + service)
	baseGrade := analyzer.HealthStatus(max(int(report.Handshake.OverallGrade), int(report.Chain.OverallGrade)))
	report.Verdicts = education.EvaluateDualVerdict(baseGrade, report.Warnings)
	report.OverallStatus = report.Verdicts.ServiceVerdict // backwards compat

	// Render output
	if flagJSON {
		return renderJSON(report)
	}

	renderReport(report)

	// Save certs if requested
	if isSaveRequested(cmd) {
		if err := saveCerts(chain, host, flagSave); err != nil {
			fmt.Println(ui.Theme.ErrorStyle.Render(fmt.Sprintf("\n[FAIL] Save error: %s", err)))
		}
	}

	return nil
}

func parseTarget(target string) (string, string) {
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimSuffix(target, "/")

	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return target, "443"
	}
	return host, port
}

func worstOverall(report *analyzer.DiagnosticReport) analyzer.HealthStatus {
	status := analyzer.MainCharacterEnergy
	status = analyzer.HealthStatus(max(int(status), int(report.Handshake.OverallGrade)))
	status = analyzer.HealthStatus(max(int(status), int(report.Chain.OverallGrade)))
	for _, w := range report.Warnings {
		status = analyzer.HealthStatus(max(int(status), int(w.Severity)))
	}
	return status
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// verbosityLevel returns a numeric verbosity for functions that still
// take an int (like RenderChainDiagram). 0 = default, 1 = details, 2 = PEM.
func verbosityLevel() int {
	if flagVerbose {
		return 2
	}
	if flagDetails {
		return 1
	}
	return 0
}

func renderReport(report *analyzer.DiagnosticReport) {
	// Always: Summary header (connection info + verdict + findings at a glance)
	fmt.Println(ui.RenderSummaryHeader(
		report.Target.Host,
		report.Target.Port,
		report.Target.IP,
		report.Target.Protocol,
		report,
	))

	// -d / --details / --gaze: Show detailed cert cards
	if flagDetails {
		for _, cert := range report.Chain.Certificates {
			fmt.Println(ui.RenderCertCard(cert))
		}
	}

	// Always: Chain diagram (with serial/fingerprint)
	fmt.Println(ui.RenderChainDiagram(report.Chain, verbosityLevel()))

	// -v / --verbose / --stare: Show PEM encoded certs + raw x509 (after chain)
	if flagVerbose {
		for _, cert := range report.Chain.Certificates {
			name := cert.CommonName
			if name == "" {
				name = cert.Subject
			}
			pemBlock := &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.RawCert.Raw,
			}
			pemData := pem.EncodeToMemory(pemBlock)

			var lines []string
			lines = append(lines, ui.Theme.BoldStyle.Render(fmt.Sprintf("PEM  %s  (%s)", name, cert.Role)))
			lines = append(lines, ui.Theme.MutedStyle.Render(string(pemData)))
			fmt.Println(ui.ApplyBorder(lines, ui.CardBorder))
		}
		// -v also includes raw x509 output
		renderRawX509(report.Chain)
	}

	// -r / --raw / --ogle: Show raw x509 text output (standalone, without PEM)
	if flagRaw && !flagVerbose {
		renderRawX509(report.Chain)
	}

	// FINDINGS section: only with -d/--details/--explain (default already shows in header + chain)
	if len(report.Warnings) > 0 && (flagDetails || flagExplain) {
		fmt.Println(ui.RenderWarnings(report.Warnings, flagExplain))
	}

	// Scan duration
	duration := fmt.Sprintf("  Scan completed in %s", report.ScanDuration.Round(time.Millisecond))
	if flagExplain {
		duration += ui.Theme.MutedStyle.Render(fmt.Sprintf(" — %s", ui.RandomScanComment()))
	}
	fmt.Println(ui.Theme.MutedStyle.Render(duration))
}

func renderJSON(report *analyzer.DiagnosticReport) error {
	// JSON cert with optional PEM and role explanation
	type jsonCert struct {
		analyzer.CertAnalysis
		RoleExplanation string `json:"role_explanation,omitempty"`
		PEM             string `json:"pem,omitempty"`
	}

	// JSON chain with enriched certs
	type jsonChain struct {
		Certificates                []jsonCert           `json:"certificates"`
		ChainLength                 int                  `json:"chain_length"`
		HasMissingIntermediate      bool                 `json:"has_missing_intermediate"`
		HasUnnecessaryRoot          bool                 `json:"has_unnecessary_root"`
		LeafOnlyMissingIntermediate bool                 `json:"leaf_only_missing_intermediate"`
		NoIssuingCAInResponse       bool                 `json:"no_issuing_ca_in_response"`
		ChainOrderCorrect           bool                 `json:"chain_order_correct"`
		TrustStoreVerified          bool                 `json:"trust_store_verified"`
		VerificationError           string               `json:"verification_error,omitempty"`
		OverallGrade                analyzer.HealthStatus `json:"overall_grade"`
	}

	type jsonReport struct {
		Target         analyzer.TargetInfo        `json:"target"`
		Handshake      analyzer.HandshakeAnalysis `json:"handshake"`
		Chain          jsonChain                  `json:"chain"`
		Warnings       []analyzer.Warning         `json:"warnings"`
		OverallStatus  analyzer.HealthStatus      `json:"overall_status"`
		Verdicts       analyzer.DualVerdict       `json:"verdicts"`
		Details        bool                       `json:"details"`
		Verbose        bool                       `json:"verbose"`
		ScanDurationMs int64                      `json:"scan_duration_ms"`
		Timestamp      time.Time                  `json:"timestamp"`
	}

	// Build enriched cert list
	var certs []jsonCert
	for _, c := range report.Chain.Certificates {
		jc := jsonCert{CertAnalysis: c}

		// -d/--details: include role explanation
		if flagDetails {
			jc.RoleExplanation = c.Role.RoleExplanation()
		}

		// -v/--verbose: include PEM encoded cert
		if flagVerbose && c.RawCert != nil {
			pemData := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: c.RawCert.Raw,
			})
			jc.PEM = string(pemData)
		}

		certs = append(certs, jc)
	}

	chain := jsonChain{
		Certificates:                certs,
		ChainLength:                 report.Chain.ChainLength,
		HasMissingIntermediate:      report.Chain.HasMissingIntermediate,
		HasUnnecessaryRoot:          report.Chain.HasUnnecessaryRoot,
		LeafOnlyMissingIntermediate: report.Chain.LeafOnlyMissingIntermediate,
		NoIssuingCAInResponse:       report.Chain.NoIssuingCAInResponse,
		ChainOrderCorrect:           report.Chain.ChainOrderCorrect,
		TrustStoreVerified:          report.Chain.TrustStoreVerified,
		VerificationError:           report.Chain.VerificationError,
		OverallGrade:                report.Chain.OverallGrade,
	}
	// Warnings: strip explain/fix/doc_ref unless --explain is set
	warnings := report.Warnings
	if !flagExplain {
		stripped := make([]analyzer.Warning, len(warnings))
		for i, w := range warnings {
			stripped[i] = analyzer.Warning{
				Code:     w.Code,
				Severity: w.Severity,
				Title:    w.Title,
				Detail:   w.Detail,
			}
		}
		warnings = stripped
	}
	// Sanitize all warning string fields for clean JSON output
	warnings = sanitizeWarnings(warnings)

	out := jsonReport{
		Target:         report.Target,
		Handshake:      report.Handshake,
		Chain:          chain,
		Warnings:       warnings,
		OverallStatus:  report.OverallStatus,
		Verdicts:       report.Verdicts,
		Details:        flagDetails,
		Verbose:        flagVerbose,
		ScanDurationMs: report.ScanDuration.Milliseconds(),
		Timestamp:      report.Timestamp,
	}

	data, err := marshalCleanJSON(out)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Println(string(data))
	return nil
}
