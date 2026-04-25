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

var chainCmd = &cobra.Command{
	Use:   "chain <host>[:<port>]",
	Short: "Show the certificate chain of trust",
	Long: `Focus on the certificate chain hierarchy. Shows a visual tree
diagram of the chain of trust — who signed what, and whether
the chain is complete and correctly ordered.

Examples:
  peep chain example.com
  peep chain example.com:8443
  peep chain --why example.com`,
	Args: cobra.ExactArgs(1),
	RunE: runChain,
}

func init() {
	rootCmd.AddCommand(chainCmd)
}

func runChain(cmd *cobra.Command, args []string) error {
	target := args[0]

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

	result, err := probe.Probe(probe.ProbeOptions{
		Host:    host,
		Port:    port,
		Timeout: time.Duration(flagTimeout) * time.Second,
		Proto:   flagProto,
	})
	if err != nil {
		fmt.Println(ui.Theme.ErrorStyle.Render(fmt.Sprintf("\n[FAIL] Failed to connect: %s", err)))
		return nil
	}

	fmt.Println(ui.RenderBanner(result.Host, result.Port, result.IP, result.Protocol))

	chain := analyzer.AnalyzeChain(result.ConnState, host, flagInsecure)

	// Cert details: Leaf → Intermediate → Root
	for _, cert := range chain.Certificates {
		fmt.Println(ui.RenderCertCard(cert))
	}

	// Chain diagram
	fmt.Println(ui.RenderChainDiagram(chain))

	return nil
}
