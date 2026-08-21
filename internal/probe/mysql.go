package probe

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"time"
)

// probeMySQLSSL performs a MySQL SSL negotiation to extract TLS state.
func probeMySQLSSL(target, hostname string, timeout time.Duration) (*tls.ConnectionState, []string, error) {
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

	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, notes, fmt.Errorf("failed to read MySQL handshake header: %w", err)
	}

	payloadLen := int(header[0]) | (int(header[1]) << 8) | (int(header[2]) << 16)
	if payloadLen == 0 || payloadLen > 0xFFFFFF {
		return nil, notes, fmt.Errorf("invalid MySQL handshake payload length: %d", payloadLen)
	}

	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, notes, fmt.Errorf("failed to read MySQL handshake payload: %w", err)
	}

	if len(payload) < 1 || payload[0] != 10 {
		return nil, notes, fmt.Errorf("unsupported MySQL protocol version (expected 10)")
	}

	// Find null terminator for server version
	nullIdx := bytes.IndexByte(payload[1:], 0x00)
	if nullIdx == -1 {
		return nil, notes, fmt.Errorf("malformed MySQL handshake: missing server version terminator")
	}
	serverVersion := string(payload[1 : 1+nullIdx])
	notes = append(notes, fmt.Sprintf("MySQL Server Version: %s", serverVersion))

	idx := 1 + nullIdx + 1 // Start of thread ID
	idx += 4               // Skip thread ID
	idx += 8               // Skip auth plugin data part 1
	idx += 1               // Skip filler

	if idx+2 > len(payload) {
		return nil, notes, fmt.Errorf("malformed MySQL handshake: missing capability flags")
	}

	capsLower := uint32(payload[idx]) | (uint32(payload[idx+1]) << 8)
	idx += 2 // Skip lower caps
	idx += 1 // Skip charset
	idx += 2 // Skip status flags

	var capsUpper uint32
	if idx+2 <= len(payload) {
		capsUpper = uint32(payload[idx]) | (uint32(payload[idx+1]) << 8)
	}

	capabilities := capsLower | (capsUpper << 16)

	// CLIENT_SSL is bit 11 (0x00000800)
	if (capabilities & 0x0800) == 0 {
		notes = append(notes, "⚠️  MySQL server does not support SSL (CLIENT_SSL capability flag not set)")
		return nil, notes, fmt.Errorf("MySQL server does not support SSL")
	}

	notes = append(notes, "MySQL server supports SSL, sending SSL Request packet")

	// Build SSL Request Packet
	// Capabilities: 0x00008A05
	// Max packet size: 16MB (0x01000000) -> little endian: 0x00, 0x00, 0x00, 0x01
	// Charset: 0x21 (utf8_general_ci)
	// 23 zero bytes
	sslReqPayload := make([]byte, 32)
	sslReqPayload[0] = 0x05 // Capabilities lower
	sslReqPayload[1] = 0x8A
	sslReqPayload[2] = 0x00 // Capabilities upper
	sslReqPayload[3] = 0x00

	sslReqPayload[4] = 0x00 // Max packet size
	sslReqPayload[5] = 0x00
	sslReqPayload[6] = 0x00
	sslReqPayload[7] = 0x01

	sslReqPayload[8] = 0x21 // Charset

	// The remaining 23 bytes are already initialized to 0

	sslReqHeader := []byte{0x20, 0x00, 0x00, 0x01} // length 32, seq 1
	sslReqPacket := append(sslReqHeader, sslReqPayload...)

	if _, err := conn.Write(sslReqPacket); err != nil {
		return nil, notes, fmt.Errorf("failed to send MySQL SSL Request: %w", err)
	}

	// Clear deadline
	conn.SetDeadline(time.Time{})

	// Upgrade to TLS
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         hostname,
	}

	tlsConn := tls.Client(conn, tlsConf)
	if err := tlsConn.Handshake(); err != nil {
		return nil, notes, fmt.Errorf("TLS handshake failed after MySQL SSL Request: %w", err)
	}

	state := tlsConn.ConnectionState()
	notes = append(notes, "MySQL TLS upgrade successful — connection is now encrypted")

	return &state, notes, nil
}
