package cli

import (
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
  peep example.com              Check HTTPS (port 443)
  peep example.com:8443         Check a custom HTTPS port
  peep mail.example.com:587     Check SMTP (auto-detects STARTTLS)
  peep rdp.example.com:3389     Check RDP (auto-handles X.224)
  peep scan example.com         Deep scan with cipher enumeration
  peep --proto smtp server:2525 Force SMTP protocol on non-standard port`,
	Args: cobra.MaximumNArgs(1),
	RunE: runPeep,
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&flagPort, "port", "p", "", "Override port (default: auto-detect)")
	rootCmd.PersistentFlags().StringVar(&flagProto, "proto", "", "Force protocol: tls, smtp, rdp, ldap, ftp (default: auto-detect by port)")
	rootCmd.PersistentFlags().IntVarP(&flagTimeout, "timeout", "t", 5, "Connection timeout in seconds")
	rootCmd.PersistentFlags().BoolVar(&flagJSON, "json", false, "Output as JSON (for scripting)")
	rootCmd.PersistentFlags().BoolVar(&flagNoColor, "no-color", false, "Disable color output")
	rootCmd.PersistentFlags().BoolVar(&flagInsecure, "insecure", false, "Skip system trust store verification")
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}

func runPeep(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return cmd.Help()
	}

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
		Handshake:    handshake,
		Chain:        chain,
		OverallStatus: analyzer.MainCharacterEnergy,
		ScanDuration: time.Since(startTime),
		Timestamp:    time.Now(),
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
	// Summary header (connection info + verdict + findings at a glance)
	fmt.Println(ui.RenderSummaryHeader(
		report.Target.Host,
		report.Target.Port,
		report.Target.IP,
		report.Target.Protocol,
		report,
	))

	// Detailed sections below:

	// Cert details: Leaf → Intermediate → Root
	for _, cert := range report.Chain.Certificates {
		fmt.Println(ui.RenderCertCard(cert))
		fmt.Println()
	}

	// Chain diagram
	fmt.Println(ui.RenderChainDiagram(report.Chain))

	// Handshake details
	fmt.Println(ui.RenderHandshakeCard(report.Handshake))

	// Warnings with --why
	if len(report.Warnings) > 0 {
		fmt.Println(ui.RenderWarnings(report.Warnings))
	}

	// Scan duration
	fmt.Println(ui.Theme.MutedStyle.Render(
		fmt.Sprintf("  Scan completed in %s", report.ScanDuration.Round(time.Millisecond)),
	))
}

func renderJSON(report *analyzer.DiagnosticReport) error {
	fmt.Fprintf(os.Stderr, "JSON output is planned for a future release.\n")
	_ = report
	return nil
}
