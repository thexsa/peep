package cli

import (
	"fmt"
	"strings"

	"github.com/thexsa/peep/internal/ui"
)

var flagExamples bool // --examples / --show-me

// exampleSet holds the examples for a single command context.
type exampleSet struct {
	heading  string
	examples []example
	jqTip    bool // whether to show the jq install tip
}

type example struct {
	description string
	command     string
}

// showExamples prints contextual examples and returns true if the flag was set.
// Call at the top of each RunE to short-circuit before any real work.
func showExamples(cmdName string) bool {
	if !flagExamples {
		return false
	}

	es := getExamples(cmdName)
	renderExamples(es)
	return true
}

func getExamples(cmdName string) exampleSet {
	switch cmdName {
	case "scan":
		return scanExamples()
	case "portscan":
		return portscanExamples()
	case "find-certs":
		return findCertsExamples()
	case "docs":
		return docsExamples()
	case "update":
		return updateExamples()
	case "version":
		return versionExamples()
	default:
		return rootExamples()
	}
}

// ─────────────────────────────────────────────
// Root: peep <host>
// ─────────────────────────────────────────────
func rootExamples() exampleSet {
	return exampleSet{
		heading: "peep — Quick Certificate Check",
		jqTip:   true,
		examples: []example{
			{
				description: "Quick check on port 443:",
				command:     "peep your.endpoint.com",
			},
			{
				description: "Check a specific port:",
				command:     "peep your.domain.com:8443",
			},
			{
				description: "SMTP with STARTTLS:",
				command:     "peep mail.company.com:587",
			},
			{
				description: "Get detailed cert cards and explanations for every finding:",
				command:     "peep your.endpoint.com --whytho --details",
			},
			{
				description: "Full verbose output with PEM certs and explanations:",
				command:     "peep your.endpoint.com --verbose --whytho",
			},
			{
				description: "Save all certificate PEMs to files:",
				command:     "peep your.endpoint.com --save",
			},
			{
				description: "Output as JSON and pipe to jq to extract specific data:",
				command:     "peep your.domain.com --json | jq '.overall_status'",
			},
			{
				description: "Extract expiration info for all certs in the chain:",
				command:     "peep your.domain.com --json | jq '.chain.certificates[] | {subject, days_remaining, not_after}'",
			},
			{
				description: "Extract just the leaf certificate PEM (requires -v):",
				command:     "peep your.domain.com --json -v | jq -r '.chain.certificates[0].pem'",
			},
			{
				description: "Get all warnings with fix recommendations (requires -e):",
				command:     "peep your.domain.com --json -e | jq '.warnings[] | {title, fix}'",
			},
			{
				description: "TCP connectivity check (like telnet/netcat) — no TLS:",
				command:     "peep -c your.endpoint.com:3389",
			},
			{
				description: "Connectivity check with JSON output:",
				command:     "peep -c -j your.endpoint.com:443",
			},
		},
	}
}

// ─────────────────────────────────────────────
// Scan: peep scan <host>
// ─────────────────────────────────────────────
func scanExamples() exampleSet {
	return exampleSet{
		heading: "peep scan — Deep Scan",
		jqTip:   true,
		examples: []example{
			{
				description: "Full deep scan on default port (OCSP, CRL, CT, ciphers, TLS versions):",
				command:     "peep scan your.endpoint.com",
			},
			{
				description: "Deep scan with explanations and fix recommendations:",
				command:     "peep scan your.endpoint.com --whytho",
			},
			{
				description: "Scan an internal server with a custom CA bundle:",
				command:     "peep scan internal.corp.local --internal-ca --ca-bundle /path/to/ca.pem",
			},
			{
				description: "Output as JSON and extract supported cipher suites:",
				command:     "peep scan your.domain.com --json | jq '.cipher_enum.supported_suites[] | .name'",
			},
			{
				description: "Check which TLS versions the server supports:",
				command:     "peep scan your.domain.com --json | jq '.tls_versions'",
			},
			{
				description: "Get OCSP and CRL revocation status:",
				command:     "peep scan your.domain.com --json | jq '{ocsp: .ocsp.status_text, crl: .crl.status}'",
			},
			{
				description: "Extract Certificate Transparency log entries:",
				command:     "peep scan your.domain.com --json | jq '.ct.scts[] | {log: .log_name, timestamp: .timestamp}'",
			},
		},
	}
}

// ─────────────────────────────────────────────
// Docs: peep docs
// ─────────────────────────────────────────────
func docsExamples() exampleSet {
	return exampleSet{
		heading: "peep docs — Built-in TLS Reference",
		jqTip:   true,
		examples: []example{
			{
				description: "Show the table of contents:",
				command:     "peep docs",
			},
			{
				description: "Read a specific topic:",
				command:     "peep docs certs",
			},
			{
				description: "Search all topics for a keyword:",
				command:     "peep docs --search \"revocation\"",
			},
			{
				description: "Display all documentation at once (man-page style):",
				command:     "peep docs --all",
			},
			{
				description: "Output a single topic as JSON:",
				command:     "peep docs crl --json | jq '.content[:5]'",
			},
			{
				description: "List all available topics as JSON:",
				command:     "peep docs --json | jq '.[].name'",
			},
			{
				description: "Search and get matching topics as JSON:",
				command:     "peep docs --search cipher --json | jq '.[].title'",
			},
		},
	}
}

// ─────────────────────────────────────────────
// Update: peep update
// ─────────────────────────────────────────────
func updateExamples() exampleSet {
	return exampleSet{
		heading: "peep update — Self-Update",
		jqTip:   false,
		examples: []example{
			{
				description: "Check if a new version is available (without installing):",
				command:     "peep update --check",
			},
			{
				description: "Update to the latest version:",
				command:     "peep update",
			},
			{
				description: "Force update even if already on the latest version:",
				command:     "peep update --force",
			},
		},
	}
}

// ─────────────────────────────────────────────
// Version: peep version
// ─────────────────────────────────────────────
func versionExamples() exampleSet {
	return exampleSet{
		heading: "peep version — Version Info",
		jqTip:   false,
		examples: []example{
			{
				description: "Show version, install method, and platform:",
				command:     "peep version",
			},
		},
	}
}

// ─────────────────────────────────────────────
// Rendering
// ─────────────────────────────────────────────
func renderExamples(es exampleSet) {
	var b strings.Builder

	// Header
	title := fmt.Sprintf("  %s", es.heading)
	separator := strings.Repeat("═", len(es.heading)+2)
	b.WriteString(ui.Theme.BoldStyle.Render(title))
	b.WriteString("\n")
	b.WriteString(ui.Theme.MutedStyle.Render("  " + separator))
	b.WriteString("\n\n")

	for _, ex := range es.examples {
		// Description line
		b.WriteString(ui.Theme.MutedStyle.Render("  " + ex.description))
		b.WriteString("\n")
		// Command line (bold, with $ prompt)
		b.WriteString(ui.Theme.InfoStyle.Render("    $ " + ex.command))
		b.WriteString("\n\n")
	}

	// jq tip
	if es.jqTip {
		b.WriteString(ui.Theme.MutedStyle.Render("  💡 Tip: Install jq (https://jqlang.github.io/jq/) for easy JSON extraction."))
		b.WriteString("\n")
	}

	fmt.Println(b.String())
}

// ─────────────────────────────────────────────
// Portscan: peep portscan <host>
// ─────────────────────────────────────────────
func portscanExamples() exampleSet {
	return exampleSet{
		heading: "peep portscan — TCP Port Scanner",
		jqTip:   true,
		examples: []example{
			{
				description: "Scan the top 50 ports:",
				command:     "peep portscan example.com",
			},
			{
				description: "Full scan — all 65,535 ports:",
				command:     "peep portscan --full example.com",
			},
			{
				description: "JSON output — list open ports:",
				command:     "peep portscan -j example.com | jq '.open_ports[].port'",
			},
			{
				description: "JSON — filter for specific services:",
				command:     "peep portscan -j example.com | jq '.open_ports[] | select(.service == \"HTTPS\")'",
			},
		},
	}
}

// ─────────────────────────────────────────────
// Find-certs: peep find-certs <host>
// ─────────────────────────────────────────────
func findCertsExamples() exampleSet {
	return exampleSet{
		heading: "peep find-certs — Certificate Discovery",
		jqTip:   true,
		examples: []example{
			{
				description: "Discover certificates on top 50 ports:",
				command:     "peep find-certs example.com",
			},
			{
				description: "Full discovery — all 65,535 ports:",
				command:     "peep find-certs --full example.com",
			},
			{
				description: "JSON output — list all discovered subjects:",
				command:     "peep find-certs -j example.com | jq '.certificates[].subject'",
			},
			{
				description: "JSON — find expiring certificates:",
				command:     "peep find-certs -j example.com | jq '.certificates[] | select(.status == \"expiring\")'",
			},
			{
				description: "JSON — show ports with self-signed certs:",
				command:     "peep find-certs -j example.com | jq '.certificates[] | select(.is_self_signed) | .port'",
			},
		},
	}
}
