package cli

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/thexsa/peep/internal/analyzer"
	"github.com/thexsa/peep/internal/probe"
	"github.com/thexsa/peep/internal/ui"
)

var scanCmd = &cobra.Command{
	Use:   "scan <host>[:<port>]",
	Short: "🔬 Deep scan — cipher enumeration, OCSP, and CT log checks",
	Long: `Perform a comprehensive scan that goes beyond the basic peep check.
This includes:

  • All checks from the default 'peep' command
  • Cipher suite enumeration (which ciphers does the server support?)
  • TLS version probing (which versions are enabled?)
  • OCSP revocation checking (has the cert been revoked?)
  • Certificate Transparency log verification (is the cert in CT logs?)

Note: This scan takes longer because it makes multiple connections
to test each cipher suite individually.

Examples:
  peep scan example.com
  peep scan --why example.com
  peep scan --rude example.com`,
	Args: cobra.ExactArgs(1),
	RunE: runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	target := args[0]

	// Strip protocol prefix
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimSuffix(target, "/")

	host, port, err := net.SplitHostPort(target)
	if err != nil {
		host = target
		port = "443"
	}
	if flagPort != "" {
		port = flagPort
	}

	personality := analyzer.Normal
	if flagRude {
		personality = analyzer.Rude
	}

	timeout := time.Duration(flagTimeout) * time.Second

	// Step 1: Regular probe
	fmt.Println(ui.Theme.InfoStyle.Render("🔬 Starting deep scan..."))
	fmt.Println()

	result, err := probe.Probe(probe.ProbeOptions{
		Host:    host,
		Port:    port,
		Timeout: timeout,
		Proto:   flagProto,
	})
	if err != nil {
		fmt.Println(ui.Theme.ErrorStyle.Render(fmt.Sprintf("\n❌ Failed to connect: %s", err)))
		return nil
	}

	// Banner
	fmt.Println(ui.RenderBanner(result.Host, result.Port, result.IP, result.Protocol))

	// Standard analysis
	handshake := analyzer.AnalyzeHandshake(result.ConnState)
	chain := analyzer.AnalyzeChain(result.ConnState, host, flagInsecure)

	// Handshake card
	fmt.Println(ui.RenderHandshakeCard(handshake, personality))

	// Chain diagram
	fmt.Println(ui.RenderChainDiagram(chain, personality))

	// Step 2: OCSP check (for leaf cert)
	if len(chain.Certificates) > 0 {
		leaf := chain.Certificates[0]
		fmt.Println(ui.Theme.MutedStyle.Render("  🔍 Checking OCSP revocation status..."))

		if len(result.ConnState.PeerCertificates) >= 2 {
			ocspResult := analyzer.CheckOCSP(
				result.ConnState.PeerCertificates[0],
				result.ConnState.PeerCertificates[1],
				timeout,
			)
			fmt.Println(ui.RenderOCSPResult(ocspResult, personality))
		} else if leaf.IsSelfSigned {
			fmt.Println(ui.Theme.MutedStyle.Render("  ⏭️  Skipping OCSP — self-signed cert"))
			fmt.Println()
		} else {
			fmt.Println(ui.Theme.MutedStyle.Render("  ⏭️  Skipping OCSP — no issuer cert available"))
			fmt.Println()
		}

		// Step 3: CT log check
		fmt.Println(ui.Theme.MutedStyle.Render("  📜 Checking Certificate Transparency logs..."))
		ctResult := analyzer.CheckCTLogs(leaf.SerialNumber, leaf.CommonName, timeout*2)
		fmt.Println(ui.RenderCTLogResult(ctResult, personality))
	}

	// Step 4: Cipher suite enumeration
	fmt.Println(ui.Theme.MutedStyle.Render("  🔐 Enumerating supported cipher suites (this may take a moment)..."))
	cipherResult := analyzer.EnumerateCiphers(host, port, timeout)
	fmt.Println(ui.RenderCipherEnum(cipherResult, personality))

	// Cert cards
	for _, cert := range chain.Certificates {
		fmt.Println(ui.RenderCertCard(cert, personality))
	}

	// Overall
	overallStatus := chain.OverallGrade
	if handshake.OverallGrade > overallStatus {
		overallStatus = handshake.OverallGrade
	}
	fmt.Println(ui.RenderOverallStatus(overallStatus, personality))

	return nil
}
