package probe

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// probePOP3StartTLS performs a POP3 STLS upgrade to extract TLS state.
func probePOP3StartTLS(target, hostname string, timeout time.Duration) (*tls.ConnectionState, []string, error) {
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

	// Read the POP3 greeting banner (+OK)
	banner, err := reader.ReadString('\n')
	if err != nil {
		return nil, notes, fmt.Errorf("failed to read POP3 greeting: %w", err)
	}
	notes = append(notes, fmt.Sprintf("POP3 Banner: %s", strings.TrimSpace(banner)))

	if !strings.HasPrefix(banner, "+OK") {
		return nil, notes, fmt.Errorf("invalid POP3 greeting: %s", strings.TrimSpace(banner))
	}

	// Send STLS command
	_, err = fmt.Fprintf(conn, "STLS\r\n")
	if err != nil {
		return nil, notes, fmt.Errorf("failed to send STLS: %w", err)
	}

	stlsResp, err := reader.ReadString('\n')
	if err != nil {
		return nil, notes, fmt.Errorf("failed to read STLS response: %w", err)
	}

	if !strings.HasPrefix(stlsResp, "+OK") {
		notes = append(notes, "⚠️  STLS command rejected — this POP3 server might not support encryption.")
		return nil, notes, fmt.Errorf("POP3 server rejected STLS: %s", strings.TrimSpace(stlsResp))
	}
	notes = append(notes, "STLS accepted — upgrading to TLS")

	// Upgrade to TLS
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         hostname,
	}

	tlsConn := tls.Client(conn, tlsConf)
	if err := tlsConn.Handshake(); err != nil {
		return nil, notes, fmt.Errorf("TLS handshake failed after STLS: %w", err)
	}

	state := tlsConn.ConnectionState()
	notes = append(notes, "POP3 TLS upgrade successful — connection is now encrypted")

	// Clean up: send QUIT via TLS
	fmt.Fprintf(tlsConn, "QUIT\r\n")

	return &state, notes, nil
}
