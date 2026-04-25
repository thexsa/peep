package probe

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// probeFTPStartTLS performs an FTP AUTH TLS upgrade to extract TLS state.
// This handles port 21 (standard FTP control channel).
func probeFTPStartTLS(target, hostname string, timeout time.Duration) (*tls.ConnectionState, []string, error) {
	var notes []string

	// Step 1: Open raw TCP connection
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

	// Step 2: Read the FTP greeting (220 banner)
	banner, err := readFTPResponse(reader)
	if err != nil {
		return nil, notes, fmt.Errorf("failed to read FTP greeting: %w", err)
	}
	notes = append(notes, fmt.Sprintf("FTP Banner: %s", strings.TrimSpace(banner)))

	// Step 3: Send AUTH TLS
	_, err = fmt.Fprintf(conn, "AUTH TLS\r\n")
	if err != nil {
		return nil, notes, fmt.Errorf("failed to send AUTH TLS: %w", err)
	}

	authResp, err := readFTPResponse(reader)
	if err != nil {
		return nil, notes, fmt.Errorf("failed to read AUTH TLS response: %w", err)
	}

	// 234 = AUTH TLS accepted
	if !strings.HasPrefix(authResp, "234") {
		// Try AUTH SSL as fallback
		_, err = fmt.Fprintf(conn, "AUTH SSL\r\n")
		if err != nil {
			return nil, notes, fmt.Errorf("failed to send AUTH SSL: %w", err)
		}

		authResp, err = readFTPResponse(reader)
		if err != nil {
			return nil, notes, fmt.Errorf("failed to read AUTH SSL response: %w", err)
		}

		if !strings.HasPrefix(authResp, "234") {
			notes = append(notes, "⚠️  Neither AUTH TLS nor AUTH SSL accepted — this FTP server doesn't support encryption.")
			return nil, notes, fmt.Errorf("FTP server rejected AUTH TLS/SSL: %s", strings.TrimSpace(authResp))
		}
		notes = append(notes, "AUTH SSL accepted (legacy — AUTH TLS is preferred)")
	} else {
		notes = append(notes, "AUTH TLS accepted — upgrading to TLS")
	}

	// Step 4: Upgrade connection to TLS
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         hostname,
	}

	tlsConn := tls.Client(conn, tlsConf)
	if err := tlsConn.Handshake(); err != nil {
		return nil, notes, fmt.Errorf("TLS handshake failed after AUTH TLS: %w", err)
	}

	state := tlsConn.ConnectionState()
	notes = append(notes, "FTP TLS upgrade successful — connection is now encrypted")

	// Clean up: send QUIT
	fmt.Fprintf(tlsConn, "QUIT\r\n")

	return &state, notes, nil
}

// readFTPResponse reads a (possibly multi-line) FTP response.
// Multi-line responses use "NNN-" for continuation and "NNN " for the final line.
func readFTPResponse(reader *bufio.Reader) (string, error) {
	var response strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return response.String(), err
		}
		response.WriteString(line)

		// Single-line response or final line of multi-line
		if len(line) >= 4 && line[3] == ' ' {
			break
		}
		// Also break if it's a short line (some servers are quirky)
		if len(line) < 4 {
			break
		}
	}
	return response.String(), nil
}
