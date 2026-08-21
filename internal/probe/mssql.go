package probe

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// probeMSSQLTLS performs a TDS PreLogin to extract TLS state.
func probeMSSQLTLS(target, hostname string, timeout time.Duration) (*tls.ConnectionState, []string, error) {
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

	payload := []byte{
		0x00, 0x00, 0x1A, 0x00, 0x06, // VERSION (token 0x00, offset 26, length 6)
		0x01, 0x00, 0x20, 0x00, 0x01, // ENCRYPTION (token 0x01, offset 32, length 1)
		0x02, 0x00, 0x21, 0x00, 0x01, // INSTOPT (token 0x02, offset 33, length 1)
		0x03, 0x00, 0x22, 0x00, 0x04, // THREADID (token 0x03, offset 34, length 4)
		0x04, 0x00, 0x26, 0x00, 0x01, // MARS (token 0x04, offset 38, length 1)
		0xFF,                               // Terminator
		0x0F, 0x00, 0x0F, 0xC8, 0x00, 0x00, // VERSION data
		0x01,                   // ENCRYPTION data (ENCRYPT_ON)
		0x00,                   // INSTOPT data
		0x00, 0x00, 0x00, 0x00, // THREADID data
		0x00, // MARS data
	}

	header := []byte{
		0x12,       // type: PreLogin
		0x01,       // status: EOM
		0x00, 0x2F, // length: 47 (big-endian)
		0x00, 0x00, // SPID
		0x01, // PacketID
		0x00, // Window
	}

	packet := append(header, payload...)

	if _, err := conn.Write(packet); err != nil {
		return nil, notes, fmt.Errorf("failed to send PreLogin packet: %w", err)
	}

	headerBuf := make([]byte, 8)
	if _, err := io.ReadFull(conn, headerBuf); err != nil {
		return nil, notes, fmt.Errorf("failed to read PreLogin response header: %w", err)
	}

	packetType := headerBuf[0]
	if packetType != 0x04 && packetType != 0x12 {
		return nil, notes, fmt.Errorf("unexpected PreLogin response type: 0x%02X", packetType)
	}

	length := binary.BigEndian.Uint16(headerBuf[2:4])
	if length < 8 {
		return nil, notes, fmt.Errorf("invalid PreLogin response length: %d", length)
	}

	payloadLen := int(length) - 8
	respPayload := make([]byte, payloadLen)
	if _, err := io.ReadFull(conn, respPayload); err != nil {
		return nil, notes, fmt.Errorf("failed to read PreLogin response payload: %w", err)
	}

	// Parse options
	offset := 0
	encryptVal := byte(0xFF) // unknown
	for offset+5 <= len(respPayload) {
		token := respPayload[offset]
		if token == 0xFF {
			break
		}
		optOffset := int(binary.BigEndian.Uint16(respPayload[offset+1 : offset+3]))
		optLen := int(binary.BigEndian.Uint16(respPayload[offset+3 : offset+5]))

		if token == 0x01 { // ENCRYPTION
			if optOffset < len(respPayload) && optOffset+optLen <= len(respPayload) && optLen > 0 {
				encryptVal = respPayload[optOffset]
			}
			break
		}
		offset += 5
	}

	if encryptVal == 0x00 {
		notes = append(notes, "MSSQL Server responded with ENCRYPT_OFF")
		return nil, notes, fmt.Errorf("MSSQL Server does not support encryption (ENCRYPT_OFF)")
	} else if encryptVal == 0x03 {
		notes = append(notes, "MSSQL Server responded with ENCRYPT_NOT_SUP")
		return nil, notes, fmt.Errorf("MSSQL Server does not support encryption (ENCRYPT_NOT_SUP)")
	}

	notes = append(notes, "MSSQL PreLogin successful, upgrading to TLS")

	// Clear deadline for TLS handshake
	conn.SetDeadline(time.Time{})

	// Upgrade to TLS
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         hostname,
	}

	tlsConn := tls.Client(conn, tlsConf)
	if err := tlsConn.Handshake(); err != nil {
		return nil, notes, fmt.Errorf("TLS handshake failed after MSSQL PreLogin: %w", err)
	}

	state := tlsConn.ConnectionState()
	notes = append(notes, "MSSQL TLS upgrade successful — connection is now encrypted")

	return &state, notes, nil
}
