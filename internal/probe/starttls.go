package probe

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// probeSTARTTLS performs an SMTP STARTTLS upgrade to extract TLS state.
// This handles both port 587 (submission) and port 25 (relay).
func probeSTARTTLS(target, hostname string, timeout time.Duration) (*tls.ConnectionState, []string, error) {
	var notes []string

	// Step 1: Open raw TCP connection
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.Dial("tcp", target)
	if err != nil {
		return nil, notes, fmt.Errorf("TCP connection failed: %w", err)
	}
	defer conn.Close()

	// Set a deadline for the entire SMTP conversation
	if err := conn.SetDeadline(time.Now().Add(timeout * 3)); err != nil {
		return nil, notes, fmt.Errorf("failed to set deadline: %w", err)
	}

	reader := bufio.NewReader(conn)

	// Step 2: Read the greeting banner
	banner, err := readSMTPResponse(reader)
	if err != nil {
		return nil, notes, fmt.Errorf("failed to read SMTP greeting: %w", err)
	}
	notes = append(notes, fmt.Sprintf("SMTP Banner: %s", strings.TrimSpace(banner)))

	// Step 3: Send EHLO
	_, err = fmt.Fprintf(conn, "EHLO peep\r\n")
	if err != nil {
		return nil, notes, fmt.Errorf("failed to send EHLO: %w", err)
	}

	ehloResp, err := readSMTPResponse(reader)
	if err != nil {
		return nil, notes, fmt.Errorf("failed to read EHLO response: %w", err)
	}

	// Step 4: Check for STARTTLS capability
	if !strings.Contains(strings.ToUpper(ehloResp), "STARTTLS") {
		notes = append(notes, "⚠️  STARTTLS not supported — this mail server is sending your emails on postcards. Everyone on the route can read them.")
		return nil, notes, fmt.Errorf("STARTTLS not advertised by server — connection is plaintext only")
	}

	notes = append(notes, "STARTTLS capability detected")

	// Step 5: Send STARTTLS command
	_, err = fmt.Fprintf(conn, "STARTTLS\r\n")
	if err != nil {
		return nil, notes, fmt.Errorf("failed to send STARTTLS: %w", err)
	}

	starttlsResp, err := readSMTPResponse(reader)
	if err != nil {
		return nil, notes, fmt.Errorf("failed to read STARTTLS response: %w", err)
	}

	if !strings.HasPrefix(starttlsResp, "220") {
		return nil, notes, fmt.Errorf("STARTTLS rejected by server: %s", strings.TrimSpace(starttlsResp))
	}

	notes = append(notes, "STARTTLS upgrade initiated")

	// Step 6: Upgrade connection to TLS
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         hostname,
	}

	tlsConn := tls.Client(conn, tlsConf)
	if err := tlsConn.Handshake(); err != nil {
		return nil, notes, fmt.Errorf("TLS handshake failed after STARTTLS: %w", err)
	}

	state := tlsConn.ConnectionState()
	notes = append(notes, "SMTP STARTTLS upgrade successful — connection is now encrypted")

	// Clean up: send QUIT
	fmt.Fprintf(tlsConn, "QUIT\r\n")

	return &state, notes, nil
}

// readSMTPResponse reads a multi-line SMTP response until a line with
// "NNN " (code followed by space) is encountered.
func readSMTPResponse(reader *bufio.Reader) (string, error) {
	var response strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return response.String(), err
		}
		response.WriteString(line)

		// SMTP multi-line responses use "NNN-" for continuation
		// and "NNN " for the final line
		if len(line) >= 4 && line[3] == ' ' {
			break
		}
	}
	return response.String(), nil
}
