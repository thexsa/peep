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

	"github.com/thexsa/peep/internal/ui"
)

// Top 50 ports for normal port scan (deduped from user spec, 2083 replaces duplicate 3389).
var portscanPorts = []int{
	21, 25, 110, 143, 389, 443, 587, 636, 853, 990, 993, 995,
	465, 1433, 2083, 2376, 2379, 2380, 3000, 3306, 3389, 4443,
	5061, 5222, 5432, 5671, 5986, 6443, 6514, 7443,
	8000, 8080, 8081, 8088, 8089, 8181, 8191, 8200, 8443, 8501, 8883,
	9090, 9093, 9200, 9300, 9443, 9887, 9997, 10250, 10443,
}

// Well-known service names for port display.
var serviceNames = map[int]string{
	21:    "FTP",
	22:    "SSH",
	25:    "SMTP",
	53:    "DNS",
	80:    "HTTP",
	110:   "POP3",
	143:   "IMAP",
	389:   "LDAP",
	443:   "HTTPS",
	465:   "SMTPS",
	587:   "SMTP Submission",
	636:   "LDAPS",
	853:   "DNS-over-TLS",
	990:   "FTPS",
	993:   "IMAPS",
	995:   "POP3S",
	1433:  "MSSQL",
	2083:  "cPanel HTTPS",
	2376:  "Docker TLS",
	2379:  "etcd Client",
	2380:  "etcd Peer",
	3000:  "Grafana/Dev",
	3306:  "MySQL",
	3389:  "RDP",
	4443:  "HTTPS Alt",
	5061:  "SIP TLS",
	5222:  "XMPP",
	5432:  "PostgreSQL",
	5671:  "AMQP TLS",
	5986:  "WinRM HTTPS",
	6443:  "K8s API",
	6514:  "Syslog TLS",
	7443:  "HTTPS Alt",
	8000:  "HTTP Alt",
	8080:  "HTTP Proxy",
	8081:  "HTTP Alt",
	8088:  "HTTP Alt",
	8089:  "Splunk Mgmt",
	8181:  "HTTP Alt",
	8191:  "HTTP Alt",
	8200:  "Vault",
	8443:  "HTTPS Alt",
	8501:  "Consul HTTPS",
	8883:  "MQTT TLS",
	9090:  "Prometheus",
	9093:  "Alertmanager",
	9200:  "Elasticsearch",
	9300:  "ES Transport",
	9443:  "HTTPS Alt",
	9887:  "HTTP Alt",
	9997:  "Splunk Fwd",
	10250: "Kubelet",
	10443: "HTTPS Alt",
}

var (
	flagPortscanFull bool
)

var portscanCmd = &cobra.Command{
	Use:   "portscan <host>",
	Short: "TCP port scan — check which ports are listening",
	Long: `Perform a TCP connect scan to discover open/listening ports.

This works like nmap -sT (TCP connect scan) and does NOT require root
or elevated privileges. It completes a full TCP handshake to detect
open ports — accurate and cross-platform.

Normal mode scans the top 50 common TLS/service ports.
Full mode (--full) scans all 65,535 ports.

Examples:
  peep portscan example.com              Scan top 50 ports
  peep portscan --full example.com       Scan all 65,535 ports
  peep portscan -j example.com           JSON output
  peep portscan --examples               Show detailed examples`,
	Args: cobra.MaximumNArgs(1),
	RunE: runPortscan,
}

func init() {
	portscanCmd.Flags().BoolVar(&flagPortscanFull, "full", false, "Scan all 65,535 ports instead of top 50")
	rootCmd.AddCommand(portscanCmd)
}

// portScanResult holds the result of a single port probe.
type portScanResult struct {
	Port      int    `json:"port"`
	State     string `json:"state"`
	Service   string `json:"service"`
	LatencyMs int64  `json:"latency_ms"`
}

func runPortscan(cmd *cobra.Command, args []string) error {
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

	// Strip port if provided (portscan scans many ports, not a single one)
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
	}

	timeout := time.Duration(flagTimeout) * time.Second

	// Choose port list
	var ports []int
	if flagPortscanFull {
		ports = make([]int, 65535)
		for i := range ports {
			ports[i] = i + 1
		}
	} else {
		ports = make([]int, len(portscanPorts))
		copy(ports, portscanPorts)
	}

	totalPorts := len(ports)

	// Determine concurrency
	maxWorkers := 50
	scanTimeout := timeout
	if flagPortscanFull {
		maxWorkers = 500
		if scanTimeout > 2*time.Second {
			scanTimeout = 2 * time.Second
		}
	}

	startTime := time.Now()

	if !flagJSON {
		fmt.Println(renderPortScanBanner(host, totalPorts))
	}

	// Worker pool
	var (
		results []portScanResult
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
				addr := fmt.Sprintf("%s:%d", host, port)
				probeStart := time.Now()
				conn, dialErr := net.DialTimeout("tcp", addr, scanTimeout)
				latency := time.Since(probeStart)
				if dialErr == nil {
					conn.Close()
					svc := serviceNames[port]
					if svc == "" {
						svc = "unknown"
					}
					mu.Lock()
					results = append(results, portScanResult{
						Port:      port,
						State:     "open",
						Service:   svc,
						LatencyMs: latency.Milliseconds(),
					})
					mu.Unlock()
				}

				mu.Lock()
				scanned++
				if !flagJSON {
					fmt.Printf("\r  Scanning ports... %d/%d", scanned, totalPorts)
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
		fmt.Printf("\r%s\n", strings.Repeat(" ", 50)) // clear progress line
	}

	duration := time.Since(startTime)

	// Sort results by port
	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})

	if flagJSON {
		return renderPortscanJSON(host, results, duration)
	}

	renderPortscanTable(host, results, duration)
	return nil
}

func renderPortscanJSON(host string, results []portScanResult, duration time.Duration) error {
	output := struct {
		Host       string           `json:"host"`
		OpenPorts  []portScanResult `json:"open_ports"`
		TotalOpen  int              `json:"total_open"`
		ScanTimeMs int64            `json:"scan_time_ms"`
	}{
		Host:       host,
		OpenPorts:  results,
		TotalOpen:  len(results),
		ScanTimeMs: duration.Milliseconds(),
	}
	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Println(string(data))
	return nil
}

func renderPortscanTable(host string, results []portScanResult, duration time.Duration) {
	var lines []string

	if len(results) == 0 {
		lines = append(lines, ui.Theme.WarningStyle.Render("  No open ports found"))
		lines = append(lines, ui.Theme.MutedStyle.Render("  All scanned ports were closed or filtered."))
	} else {
		// Header
		header := fmt.Sprintf("  %-8s %-8s %s", "PORT", "STATE", "SERVICE")
		lines = append(lines, ui.Theme.BoldStyle.Render(header))
		lines = append(lines, ui.Theme.MutedStyle.Render("  "+strings.Repeat("─", 40)))

		for _, r := range results {
			state := ui.Theme.SuccessStyle.Render("open")
			line := fmt.Sprintf("  %-8d %-16s %s", r.Port, state, r.Service)
			lines = append(lines, line)
		}

		lines = append(lines, "")
		lines = append(lines, ui.Theme.MutedStyle.Render(
			fmt.Sprintf("  %d open port(s) found", len(results)),
		))
	}

	lines = append(lines, ui.Theme.MutedStyle.Render(
		fmt.Sprintf("  Scan completed in %s", duration.Round(time.Millisecond)),
	))

	fmt.Println(ui.ApplyBorder(lines, ui.SectionBorder))
}

func renderPortScanBanner(host string, portCount int) string {
	modeLabel := "Normal"
	if flagPortscanFull {
		modeLabel = "Full"
	}
	lines := []string{
		ui.Theme.BoldStyle.Render(fmt.Sprintf("  Port Scanning %s", host)),
		ui.Theme.MutedStyle.Render(fmt.Sprintf("  Mode: %s (%d ports)", modeLabel, portCount)),
	}
	return ui.ApplyBorder(lines, ui.HeaderBorder)
}
