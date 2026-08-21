package probe

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"time"
)

// probePostgresSSL performs a PostgreSQL SSLRequest to extract TLS state.
func probePostgresSSL(target, hostname string, timeout time.Duration) (*tls.ConnectionState, []string, error) {
	var notes []string

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.Dial("tcp", target)
	if err != nil {
		return nil, notes, fmt.Errorf("TCP connection failed: %w", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout * 2)); err != nil {
		return nil, notes, fmt.Errorf("failed to set deadline: %w", err)
	}

	// Build SSLRequest message
	// 4 bytes length (8), 4 bytes code (80877103 = 0x04D2162F)
	sslReq := []byte{
		0x00, 0x00, 0x00, 0x08,
		0x04, 0xD2, 0x16, 0x2F,
	}

	if _, err := conn.Write(sslReq); err != nil {
		return nil, notes, fmt.Errorf("failed to send PostgreSQL SSLRequest: %w", err)
	}

	resp := make([]byte, 1)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, notes, fmt.Errorf("failed to read PostgreSQL SSLRequest response: %w", err)
	}

	if resp[0] == 'N' {
		notes = append(notes, "⚠️  PostgreSQL server refused SSLRequest ('N' response)")
		return nil, notes, fmt.Errorf("PostgreSQL server does not support SSL")
	} else if resp[0] != 'S' {
		return nil, notes, fmt.Errorf("unexpected PostgreSQL SSLRequest response: 0x%02X", resp[0])
	}

	notes = append(notes, "PostgreSQL server accepted SSLRequest ('S' response), upgrading to TLS")

	// Clear deadline
	conn.SetDeadline(time.Time{})

	// Upgrade to TLS
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         hostname,
	}

	tlsConn := tls.Client(conn, tlsConf)
	if err := tlsConn.Handshake(); err != nil {
		return nil, notes, fmt.Errorf("TLS handshake failed after PostgreSQL SSLRequest: %w", err)
	}

	state := tlsConn.ConnectionState()
	notes = append(notes, "PostgreSQL TLS upgrade successful — connection is now encrypted")

	return &state, notes, nil
}
