package probe

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// probeIMAPStartTLS performs an IMAP STARTTLS upgrade to extract TLS state.
func probeIMAPStartTLS(target, hostname string, timeout time.Duration) (*tls.ConnectionState, []string, error) {
	var notes []string

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.Dial("tcp", target)
	if err != nil {
		return nil, notes, fmt.Errorf("TCP connection failed: %w", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout * 3)); err != nil {
		return nil, notes, fmt.Errorf("failed to set deadline: %w", err)
	}

	reader := bufio.NewReader(conn)

	// Read the IMAP greeting (* OK)
	banner, err := reader.ReadString('\n')
	if err != nil {
		return nil, notes, fmt.Errorf("failed to read IMAP greeting: %w", err)
	}
	notes = append(notes, fmt.Sprintf("IMAP Banner: %s", strings.TrimSpace(banner)))

	if !strings.HasPrefix(banner, "* OK") && !strings.HasPrefix(banner, "* PREAUTH") {
		return nil, notes, fmt.Errorf("invalid IMAP greeting: %s", strings.TrimSpace(banner))
	}

	// Send CAPABILITY command
	_, err = fmt.Fprintf(conn, "a001 CAPABILITY\r\n")
	if err != nil {
		return nil, notes, fmt.Errorf("failed to send CAPABILITY: %w", err)
	}

	var hasStartTLS bool
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, notes, fmt.Errorf("failed to read CAPABILITY response: %w", err)
		}
		if strings.Contains(strings.ToUpper(line), "STARTTLS") {
			hasStartTLS = true
		}
		if strings.HasPrefix(line, "a001 ") {
			break
		}
	}

	if hasStartTLS {
		notes = append(notes, "IMAP CAPABILITY lists STARTTLS")
	} else {
		notes = append(notes, "IMAP CAPABILITY does not list STARTTLS, attempting anyway...")
	}

	// Send STARTTLS command
	_, err = fmt.Fprintf(conn, "a001 STARTTLS\r\n")
	if err != nil {
		return nil, notes, fmt.Errorf("failed to send STARTTLS: %w", err)
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, notes, fmt.Errorf("failed to read STARTTLS response: %w", err)
		}
		if strings.HasPrefix(line, "a001 ") {
			if !strings.HasPrefix(line, "a001 OK") {
				notes = append(notes, "⚠️  STARTTLS command rejected — this IMAP server might not support encryption.")
				return nil, notes, fmt.Errorf("IMAP server rejected STARTTLS: %s", strings.TrimSpace(line))
			}
			break
		}
	}

	notes = append(notes, "STARTTLS accepted — upgrading to TLS")

	// Upgrade to TLS
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         hostname,
	}

	tlsConn := tls.Client(conn, tlsConf)
	if err := tlsConn.Handshake(); err != nil {
		return nil, notes, fmt.Errorf("TLS handshake failed after STARTTLS: %w", err)
	}

	state := tlsConn.ConnectionState()
	notes = append(notes, "IMAP TLS upgrade successful — connection is now encrypted")

	// Clean up: send LOGOUT via TLS
	fmt.Fprintf(tlsConn, "a002 LOGOUT\r\n")

	return &state, notes, nil
}
