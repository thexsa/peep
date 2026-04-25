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
	flagWhy      bool
	flagTimeout  int
	flagJSON     bool
	flagNoColor  bool
	flagInsecure bool
	flagRude     bool
)

var rootCmd = &cobra.Command{
	Use:   "peep <host>[:<port>]",
	Short: "👀 peep — your digital eyes for TLS diagnostics",
	Long: `peep is a TLS diagnostic tool designed for support engineers.
It peeps into TLS handshakes and certificate chains to tell you
exactly what's wrong — in plain English, not hex dumps.

Smart protocol detection: peep automatically handles HTTPS, SMTP,
RDP, LDAP, and more. Just give it a host and port.

Examples:
  peep example.com              Check HTTPS (port 443)
  peep example.com:8443         Check a custom HTTPS port
  peep mail.example.com:587     Check SMTP (auto-detects STARTTLS)
  peep rdp.example.com:3389     Check RDP (auto-handles X.224)
  peep --why example.com        Show explanations for all warnings
  peep --rude example.com       Brutally honest mode
  peep --proto smtp server:2525 Force SMTP protocol on non-standard port`,
	Args: cobra.MaximumNArgs(1),
	RunE: runPeep,
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&flagPort, "port", "p", "", "Override port (default: auto-detect)")
	rootCmd.PersistentFlags().StringVar(&flagProto, "proto", "", "Force protocol: tls, smtp, rdp, ldap (default: auto-detect by port)")
	rootCmd.PersistentFlags().BoolVar(&flagWhy, "why", false, "Show educational explanations for every warning")
	rootCmd.PersistentFlags().IntVarP(&flagTimeout, "timeout", "t", 5, "Connection timeout in seconds")
	rootCmd.PersistentFlags().BoolVar(&flagJSON, "json", false, "Output as JSON (for scripting)")
	rootCmd.PersistentFlags().BoolVar(&flagNoColor, "no-color", false, "Disable color output")
	rootCmd.PersistentFlags().BoolVar(&flagInsecure, "insecure", false, "Skip system trust store verification")
	rootCmd.PersistentFlags().BoolVar(&flagRude, "rude", false, "Enable brutally honest mode 🌶️")
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

	personality := analyzer.Normal
	if flagRude {
		personality = analyzer.Rude
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
		fmt.Println(ui.Theme.ErrorStyle.Render(fmt.Sprintf("\n❌ Failed to connect: %s", err)))
		if flagRude {
			fmt.Println(ui.Theme.MutedStyle.Render("   Maybe try checking if the server is actually running? Just a thought."))
		} else {
			fmt.Println(ui.Theme.MutedStyle.Render("   Check that the host is reachable and the port is correct."))
		}
		return nil
	}

	// Banner
	fmt.Println(ui.RenderBanner(result.Host, result.Port, result.IP, result.Protocol))

	// Probe notes
	if len(result.ProbeNotes) > 0 {
		for _, note := range result.ProbeNotes {
			fmt.Println(ui.Theme.MutedStyle.Render("  💬 " + note))
		}
		fmt.Println()
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
		OverallStatus: analyzer.ClearSkies,
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

	renderReport(report, personality)
	return nil
}

func parseTarget(target string) (string, string) {
	// Strip protocol prefix if present
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimSuffix(target, "/")

	// Check if port is specified
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		// No port specified — default to 443
		return target, "443"
	}
	return host, port
}

func worstOverall(report *analyzer.DiagnosticReport) analyzer.HealthStatus {
	status := analyzer.ClearSkies
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

func renderReport(report *analyzer.DiagnosticReport, personality analyzer.Personality) {
	// Handshake card
	fmt.Println(ui.RenderHandshakeCard(report.Handshake, personality))

	// Chain diagram
	fmt.Println(ui.RenderChainDiagram(report.Chain, personality))

	// Detailed cert cards
	for _, cert := range report.Chain.Certificates {
		fmt.Println(ui.RenderCertCard(cert, personality))
	}

	// Warnings
	if len(report.Warnings) > 0 {
		fmt.Println(ui.RenderWarnings(report.Warnings, flagWhy, personality))
	}

	// Overall status
	fmt.Println(ui.RenderOverallStatus(report.OverallStatus, personality))

	// Scan duration
	fmt.Println(ui.Theme.MutedStyle.Render(
		fmt.Sprintf("\n  ⏱️  Scan completed in %s", report.ScanDuration.Round(time.Millisecond)),
	))
}

func renderJSON(report *analyzer.DiagnosticReport) error {
	// Simple JSON output — we'll use encoding/json
	// This is intentionally basic for v0.1; a proper JSON schema can come later
	fmt.Fprintf(os.Stderr, "JSON output is planned for a future release.\n")
	_ = report
	return nil
}
