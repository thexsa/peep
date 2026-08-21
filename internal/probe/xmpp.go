package probe

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// probeXMPPStartTLS performs an XMPP STARTTLS upgrade to extract TLS state.
func probeXMPPStartTLS(target, hostname string, timeout time.Duration) (*tls.ConnectionState, []string, error) {
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

	// Send XML stream opening
	streamOpen := fmt.Sprintf("<?xml version='1.0'?><stream:stream to='%s' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>", hostname)
	if _, err := fmt.Fprintf(conn, "%s", streamOpen); err != nil {
		return nil, notes, fmt.Errorf("failed to send XMPP stream opening: %w", err)
	}

	buf := make([]byte, 4096)
	var responseData string

	// Read until we see <stream:features
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, notes, fmt.Errorf("failed to read XMPP features: %w", err)
		}
		responseData += string(buf[:n])

		// XMPP servers might send features immediately or we might have to wait
		// In a simple check, we look for the end of the features tag or just the features tag itself.
		// Let's break if we see <stream:features and some inner content.
		// Since we just need to see if <starttls is there, we can read a chunk and check.
		// Usually it's sent in the first few packets.
		if strings.Contains(responseData, "</stream:features>") {
			break
		}

		// If we've read a decent amount or see starttls, we can also break.
		if strings.Contains(responseData, "<starttls") {
			break
		}
	}

	if !strings.Contains(responseData, "<starttls") {
		notes = append(notes, "⚠️  XMPP server features do not include <starttls>")
		return nil, notes, fmt.Errorf("XMPP server does not support STARTTLS")
	}

	notes = append(notes, "XMPP server features include STARTTLS")

	// Send STARTTLS request
	startTLSReq := "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
	if _, err := fmt.Fprintf(conn, "%s", startTLSReq); err != nil {
		return nil, notes, fmt.Errorf("failed to send XMPP STARTTLS request: %w", err)
	}

	// Read response
	responseData = ""
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, notes, fmt.Errorf("failed to read XMPP STARTTLS response: %w", err)
		}
		responseData += string(buf[:n])
		if strings.Contains(responseData, "<proceed") || strings.Contains(responseData, "<failure") {
			break
		}
	}

	if !strings.Contains(responseData, "<proceed") {
		return nil, notes, fmt.Errorf("XMPP server rejected STARTTLS: %s", responseData)
	}

	notes = append(notes, "STARTTLS <proceed> received, upgrading to TLS")

	// Clear deadline
	conn.SetDeadline(time.Time{})

	// Upgrade to TLS
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         hostname,
	}

	tlsConn := tls.Client(conn, tlsConf)
	if err := tlsConn.Handshake(); err != nil {
		return nil, notes, fmt.Errorf("TLS handshake failed after XMPP STARTTLS: %w", err)
	}

	state := tlsConn.ConnectionState()
	notes = append(notes, "XMPP TLS upgrade successful — connection is now encrypted")

	return &state, notes, nil
}
