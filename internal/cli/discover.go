package cli

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/thexsa/peep/internal/probe"
	"github.com/thexsa/peep/internal/ui"
)

// discoverPorts is the list of ports to scan for certificates in normal mode.
// Same 50 ports as portscan (deduped, 2083 replaces duplicate 3389).
var discoverPorts = []int{
	21, 25, 110, 143, 389, 443, 587, 636, 853, 990, 993, 995,
	465, 1433, 2083, 2376, 2379, 2380, 3000, 3306, 3389, 4443,
	5061, 5222, 5432, 5671, 5986, 6443, 6514, 7443,
	8000, 8080, 8081, 8088, 8089, 8181, 8191, 8200, 8443, 8501, 8883,
	9090, 9093, 9200, 9300, 9443, 9887, 9997, 10250, 10443,
}

var (
	flagDiscoverFull bool
)

var findCertsCmd = &cobra.Command{
	Use:   "find-certs <host>",
	Short: "Certificate discovery — find TLS certificates across ports",
	Long: `Discover TLS certificates across multiple ports using protocol-aware probing.

This scans ports for TLS certificates, using the correct protocol negotiation
for each port (STARTTLS for SMTP/FTP/POP3/IMAP/LDAP/XMPP, X.224 for RDP,
TDS for MSSQL, native SSL negotiation for MySQL/PostgreSQL, and direct TLS
for all other ports).

Normal mode scans the top 50 common TLS/service ports.
Full mode (--full) scans all 65,535 ports.

Examples:
  peep find-certs example.com              Scan top 50 ports for certificates
  peep find-certs --full example.com       Scan all 65,535 ports
  peep find-certs -j example.com           JSON output
  peep find-certs --examples               Show detailed examples`,
	Aliases: []string{"find-cert"},
	Args:    cobra.MaximumNArgs(1),
	RunE:    runDiscover,
}

func init() {
	findCertsCmd.Flags().BoolVar(&flagDiscoverFull, "full", false, "Scan all 65,535 ports instead of top 50")
	rootCmd.AddCommand(findCertsCmd)
}

// certDiscoveryResult holds the result of probing a single port for a certificate.
type certDiscoveryResult struct {
	Port             int    `json:"port"`
	Protocol         string `json:"protocol"`
	Subject          string `json:"subject"`
	Issuer           string `json:"issuer"`
	NotBefore        string `json:"not_before"`
	NotAfter         string `json:"not_after"`
	DaysUntilExpiry  int    `json:"days_until_expiry"`
	SerialNumber     string `json:"serial_number"`
	SignatureAlg     string `json:"signature_algorithm"`
	IsSelfSigned     bool   `json:"is_self_signed"`
	Status           string `json:"status"` // "valid", "expiring", "expired"
}

func runDiscover(cmd *cobra.Command, args []string) error {
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

	// Strip port if provided (discover scans many ports)
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
	}

	timeout := time.Duration(flagTimeout) * time.Second

	// Choose port list
	var ports []int
	if flagDiscoverFull {
		ports = make([]int, 65535)
		for i := range ports {
			ports[i] = i + 1
		}
	} else {
		ports = make([]int, len(discoverPorts))
		copy(ports, discoverPorts)
	}

	totalPorts := len(ports)

	// Determine concurrency
	maxWorkers := 100
	probeTimeout := timeout
	if flagDiscoverFull {
		maxWorkers = 500
		if probeTimeout > 2*time.Second {
			probeTimeout = 2 * time.Second
		}
	}

	startTime := time.Now()

	if !flagJSON {
		fmt.Println(renderDiscoverBanner(host, totalPorts))
	}

	// Worker pool
	var (
		results []certDiscoveryResult
		mu      sync.Mutex
		wg      sync.WaitGroup
		scanned int
	)

	portCh := make(chan int, maxWorkers)

	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portCh {
				portStr := fmt.Sprintf("%d", port)

				probeResult, probeErr := probe.Probe(probe.ProbeOptions{
					Host:    host,
					Port:    portStr,
					Timeout: probeTimeout,
				})

				if probeErr == nil && probeResult.ConnState != nil &&
					len(probeResult.ConnState.PeerCertificates) > 0 {

					cert := probeResult.ConnState.PeerCertificates[0]
					daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)

					status := "valid"
					if daysLeft <= 0 {
						status = "expired"
					} else if daysLeft <= 30 {
						status = "expiring"
					}

					isSelfSigned := cert.Subject.String() == cert.Issuer.String()

					r := certDiscoveryResult{
						Port:            port,
						Protocol:        probeResult.Protocol,
						Subject:         cert.Subject.CommonName,
						Issuer:          cert.Issuer.CommonName,
						NotBefore:       cert.NotBefore.Format("2006-01-02"),
						NotAfter:        cert.NotAfter.Format("2006-01-02"),
						DaysUntilExpiry: daysLeft,
						SerialNumber:    fmt.Sprintf("%X", cert.SerialNumber),
						SignatureAlg:    cert.SignatureAlgorithm.String(),
						IsSelfSigned:    isSelfSigned,
						Status:          status,
					}

					if cert.Subject.CommonName == "" {
						r.Subject = cert.Subject.String()
					}
					if cert.Issuer.CommonName == "" {
						r.Issuer = cert.Issuer.String()
					}

					mu.Lock()
					results = append(results, r)
					mu.Unlock()
				}

				mu.Lock()
				scanned++
				if !flagJSON {
					fmt.Printf("\r  Discovering certificates... %d/%d", scanned, totalPorts)
				}
				mu.Unlock()
			}
		}()
	}

	for _, port := range ports {
		portCh <- port
	}
	close(portCh)
	wg.Wait()

	if !flagJSON {
		fmt.Printf("\r%s\n", strings.Repeat(" ", 60)) // clear progress line
	}

	duration := time.Since(startTime)

	// Sort results by port
	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})

	if flagJSON {
		return renderDiscoverJSON(host, results, duration)
	}

	renderDiscoverTable(host, results, duration)
	return nil
}

func renderDiscoverJSON(host string, results []certDiscoveryResult, duration time.Duration) error {
	output := struct {
		Host            string                `json:"host"`
		Certificates    []certDiscoveryResult `json:"certificates"`
		TotalFound      int                   `json:"total_found"`
		ScanTimeMs      int64                 `json:"scan_time_ms"`
	}{
		Host:         host,
		Certificates: results,
		TotalFound:   len(results),
		ScanTimeMs:   duration.Milliseconds(),
	}
	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Println(string(data))
	return nil
}

func renderDiscoverTable(host string, results []certDiscoveryResult, duration time.Duration) {
	var lines []string

	if len(results) == 0 {
		lines = append(lines, ui.Theme.WarningStyle.Render("  No certificates found"))
		lines = append(lines, ui.Theme.MutedStyle.Render("  No TLS certificates were discovered on the scanned ports."))
	} else {
		// Header
		header := fmt.Sprintf("  %-7s %-22s %-28s %-22s %-12s %s", "PORT", "PROTOCOL", "SUBJECT", "ISSUER", "EXPIRES", "STATUS")
		lines = append(lines, ui.Theme.BoldStyle.Render(header))
		lines = append(lines, ui.Theme.MutedStyle.Render("  "+strings.Repeat("─", 110)))

		valid, expiring, expired := 0, 0, 0
		for _, r := range results {
			var statusIcon string
			switch r.Status {
			case "valid":
				statusIcon = ui.Theme.SuccessStyle.Render("✓")
				valid++
			case "expiring":
				statusIcon = ui.Theme.WarningStyle.Render("⚠")
				expiring++
			case "expired":
				statusIcon = ui.Theme.ErrorStyle.Render("✗")
				expired++
			}

			subject := truncate(r.Subject, 26)
			issuer := truncate(r.Issuer, 20)
			protocol := truncate(r.Protocol, 20)

			line := fmt.Sprintf("  %-7d %-22s %-28s %-22s %-12s %s",
				r.Port, protocol, subject, issuer, r.NotAfter, statusIcon)
			lines = append(lines, line)
		}

		lines = append(lines, "")
		summary := fmt.Sprintf("  Found %d certificate(s)", len(results))
		counts := []string{}
		if valid > 0 {
			counts = append(counts, fmt.Sprintf("%d valid", valid))
		}
		if expiring > 0 {
			counts = append(counts, fmt.Sprintf("%d expiring", expiring))
		}
		if expired > 0 {
			counts = append(counts, fmt.Sprintf("%d expired", expired))
		}
		if len(counts) > 0 {
			summary += " (" + strings.Join(counts, ", ") + ")"
		}
		lines = append(lines, ui.Theme.MutedStyle.Render(summary))
	}

	lines = append(lines, ui.Theme.MutedStyle.Render(
		fmt.Sprintf("  Scan completed in %s", duration.Round(time.Millisecond)),
	))

	fmt.Println(ui.ApplyBorder(lines, ui.SectionBorder))
}

func renderDiscoverBanner(host string, portCount int) string {
	modeLabel := "Normal"
	if flagDiscoverFull {
		modeLabel = "Full"
	}
	lines := []string{
		ui.Theme.BoldStyle.Render(fmt.Sprintf("  Certificate Discovery — %s", host)),
		ui.Theme.MutedStyle.Render(fmt.Sprintf("  Mode: %s (%d ports) — Protocol-aware probing", modeLabel, portCount)),
	}
	return ui.ApplyBorder(lines, ui.HeaderBorder)
}

// truncate shortens a string to maxLen, adding "…" if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 1 {
		return "…"
	}
	return s[:maxLen-1] + "…"
}
