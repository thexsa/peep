package probe

import (
	"crypto/tls"
	"net"
	"time"
)

// probeDirectTLS performs a direct TLS connection and returns the connection state.
func probeDirectTLS(target, hostname string, timeout time.Duration) (*tls.ConnectionState, []string, error) {
	var notes []string

	conf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         hostname,
	}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", target, conf)
	if err != nil {
		return nil, notes, err
	}
	defer conn.Close()

	state := conn.ConnectionState()

	// Add notes about the negotiated protocol
	notes = append(notes, "Direct TLS handshake completed successfully")

	return &state, notes, nil
}
