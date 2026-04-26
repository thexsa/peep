package cli

import (
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/thexsa/peep/internal/analyzer"
	"github.com/thexsa/peep/internal/education"
	"github.com/thexsa/peep/internal/probe"
	"github.com/thexsa/peep/internal/ui"
)

var (
	// Flags
	flagPort     string
	flagProto    string
	flagTimeout  int
	flagJSON     bool
	flagNoColor  bool
	flagInsecure bool
	flagVerbose  int  // 0 = default, 1 = -v, 2 = -vv/--verbose
	flagExplain  bool // --explain
)

var rootCmd = &cobra.Command{
	Use:   "peep <host>[:<port>]",
	Short: "peep — your digital eyes for TLS diagnostics",
	Long: `peep is a TLS diagnostic tool designed for support engineers.
It peeps into TLS handshakes and certificate chains to tell you
exactly what's wrong — in plain English, not hex dumps.

Smart protocol detection: peep automatically handles HTTPS, SMTP,
RDP, LDAP, FTP, and more. Just give it a host and port.

Examples:
  peep example.com              Quick check (header + chain)
  peep -v example.com           Show full cert details
  peep -vv example.com          Full details + PEM encoded certs
  peep --explain example.com    Explain all issues with fixes & doc refs
  peep scan example.com         Deep scan with cipher enumeration
  peep --proto smtp server:2525 Force SMTP protocol on non-standard port`,
	Args: cobra.MaximumNArgs(1),
	RunE: runPeep,
}

var flagVV bool // --verbose

func init() {
	rootCmd.PersistentFlags().StringVarP(&flagPort, "port", "p", "", "Override port (default: auto-detect)")
	rootCmd.PersistentFlags().StringVar(&flagProto, "proto", "", "Force protocol: tls, smtp, rdp, ldap, ftp (default: auto-detect by port)")
	rootCmd.PersistentFlags().IntVarP(&flagTimeout, "timeout", "t", 5, "Connection timeout in seconds")
	rootCmd.PersistentFlags().BoolVar(&flagJSON, "json", false, "Output as JSON (for scripting)")
	rootCmd.PersistentFlags().BoolVar(&flagNoColor, "no-color", false, "Disable color output")
	rootCmd.PersistentFlags().BoolVar(&flagInsecure, "insecure", false, "Skip system trust store verification")
	rootCmd.PersistentFlags().CountVarP(&flagVerbose, "v", "v", "Verbosity: -v for cert details, -vv for PEM certs")
	rootCmd.PersistentFlags().BoolVar(&flagVV, "verbose", false, "Max verbosity (same as -vv)")
	rootCmd.PersistentFlags().BoolVar(&flagExplain, "explain", false, "Explain each issue with fix recommendations and doc references")
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}

func resolveVerbosity() int {
	if flagVV {
		return 2
	}
	if flagVerbose > 2 {
		return 2
	}
	return flagVerbose
}

func runPeep(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return cmd.Help()
	}

	flagVerbose = resolveVerbosity()

	target := args[0]
	host, port := parseTarget(target)

	if flagPort != "" {
		port = flagPort
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
		fmt.Println(ui.Theme.ErrorStyle.Render(fmt.Sprintf("\n[FAIL] Failed to connect: %s", err)))
		fmt.Println(ui.Theme.MutedStyle.Render("       Maybe try checking if the server is actually running? Just a thought."))
		return nil
	}

	// Analyze
	handshake := analyzer.AnalyzeHandshake(result.ConnState)
	chain := analyzer.AnalyzeChain(result.ConnState, host, flagInsecure)

	// Build report
	report := &analyzer.DiagnosticReport{
		Target: analyzer.TargetInfo{
			Host:      result.Host,
			Port:      result.Port,
			IP:        result.IP,
			Protocol:  result.Protocol,
			ProbeType: result.ProbeType,
		},
		Handshake:     handshake,
		Chain:         chain,
		OverallStatus: analyzer.MainCharacterEnergy,
		ScanDuration:  time.Since(startTime),
		Timestamp:     time.Now(),
	}

	// Build warnings
	report.Warnings = education.BuildWarnings(report)

	// Calculate overall status
	report.OverallStatus = worstOverall(report)

	// Render output
	if flagJSON {
		return renderJSON(report)
	}

	renderReport(report)
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

func renderReport(report *analyzer.DiagnosticReport) {
	// Always: Summary header (connection info + verdict + findings at a glance)
	fmt.Println(ui.RenderSummaryHeader(
		report.Target.Host,
		report.Target.Port,
		report.Target.IP,
		report.Target.Protocol,
		report,
	))

	// -v and -vv: Show detailed cert cards
	if flagVerbose >= 1 {
		for _, cert := range report.Chain.Certificates {
			fmt.Println(ui.RenderCertCard(cert))
		}
	}

	// Always: Chain diagram (with serial/fingerprint)
	fmt.Println(ui.RenderChainDiagram(report.Chain))

	// -vv/--verbose: Show PEM encoded certs (after chain)
	if flagVerbose >= 2 {
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
	}

	// FINDINGS section: only with -v/--verbose/--explain (default already shows in header + chain)
	if len(report.Warnings) > 0 && (flagVerbose >= 1 || flagExplain) {
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
	fmt.Fprintf(os.Stderr, "JSON output is planned for a future release.\n")
	_ = report
	return nil
}
