package cli

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/thexsa/peep/internal/ui"
)

// runConnectivityCheck performs a TCP-only connectivity test to the target host:port.
// It does NOT perform any TLS handshake — just checks if the port is reachable,
// similar to how people use telnet or netcat for firewall testing.
func runConnectivityCheck(host, port string, timeout time.Duration) error {
	ipStr := "Unknown"
	ips, err := net.LookupIP(host)
	if err == nil && len(ips) > 0 {
		ipStr = ips[0].String()
	}

	target := net.JoinHostPort(host, port)
	start := time.Now()

	conn, err := net.DialTimeout("tcp", target, timeout)
	latency := time.Since(start)

	if err == nil {
		conn.Close()
	}

	if flagJSON {
		if err == nil {
			type result struct {
				Host      string `json:"host"`
				Port      string `json:"port"`
				IP        string `json:"ip"`
				Reachable bool   `json:"reachable"`
				LatencyMs int64  `json:"latency_ms"`
			}
			res := result{
				Host:      host,
				Port:      port,
				IP:        ipStr,
				Reachable: true,
				LatencyMs: latency.Milliseconds(),
			}
			out, _ := json.MarshalIndent(res, "", "  ")
			fmt.Println(string(out))
		} else {
			type result struct {
				Host      string `json:"host"`
				Port      string `json:"port"`
				IP        string `json:"ip"`
				Reachable bool   `json:"reachable"`
				Error     string `json:"error"`
			}
			res := result{
				Host:      host,
				Port:      port,
				IP:        ipStr,
				Reachable: false,
				Error:     err.Error(),
			}
			out, _ := json.MarshalIndent(res, "", "  ")
			fmt.Println(string(out))
		}
		return nil
	}

	var lines []string
	lines = append(lines, ui.Theme.BoldStyle.Render("CONNECTIVITY CHECK"))
	lines = append(lines, fmt.Sprintf("Target:    %s:%s", host, port))
	lines = append(lines, fmt.Sprintf("IP:        %s", ipStr))
	lines = append(lines, "")

	if err == nil {
		lines = append(lines, ui.Theme.SuccessStyle.Render(fmt.Sprintf("[PASS] TCP connection succeeded (latency: %dms)", latency.Milliseconds())))
	} else {
		errMsg := err.Error()
		lines = append(lines, ui.Theme.ErrorStyle.Render(fmt.Sprintf("[FAIL] TCP connection failed: %s", errMsg)))

		var hint string
		if strings.Contains(errMsg, "refused") {
			hint = "Port is not listening or is blocked by a host-level firewall."
		} else if strings.Contains(errMsg, "timeout") || strings.Contains(errMsg, "timed out") {
			hint = "No response — port may be filtered by a network firewall, or host is unreachable."
		} else if strings.Contains(errMsg, "no such host") {
			hint = "DNS resolution failed — check the hostname."
		} else {
			hint = "Check network connectivity and firewall rules."
		}
		lines = append(lines, ui.Theme.MutedStyle.Render(hint))
	}

	fmt.Println(ui.ApplyBorder(lines, ui.SectionBorder))
	return nil
}
