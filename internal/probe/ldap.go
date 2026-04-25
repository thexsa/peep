package probe

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// LDAP STARTTLS OID: 1.3.6.1.4.1.1466.20037
// We construct the ASN.1/BER-encoded Extended Request manually to avoid
// pulling in a full LDAP library dependency.

// probeLDAPStartTLS performs an LDAP Extended Operation for STARTTLS,
// then upgrades the connection to TLS.
func probeLDAPStartTLS(target, hostname string, timeout time.Duration) (*tls.ConnectionState, []string, error) {
	var notes []string

	// Step 1: Open raw TCP connection
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.Dial("tcp", target)
	if err != nil {
		return nil, notes, fmt.Errorf("TCP connection to LDAP service failed: %w", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout * 2)); err != nil {
		return nil, notes, fmt.Errorf("failed to set deadline: %w", err)
	}

	notes = append(notes, "Connected to LDAP service — sending STARTTLS Extended Request")

	// Step 2: Send LDAP Extended Request for StartTLS
	// This is a manually constructed BER-encoded LDAP message.
	// MessageID: 1
	// ExtendedRequest with OID: 1.3.6.1.4.1.1466.20037
	startTLSReq := buildLDAPStartTLSRequest()
	if _, err := conn.Write(startTLSReq); err != nil {
		return nil, notes, fmt.Errorf("failed to send LDAP STARTTLS request: %w", err)
	}

	// Step 3: Read LDAP Extended Response
	if err := readLDAPStartTLSResponse(conn); err != nil {
		return nil, notes, fmt.Errorf("LDAP STARTTLS failed: %w", err)
	}

	notes = append(notes, "LDAP server accepted STARTTLS — upgrading connection")

	// Step 4: Upgrade to TLS
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         hostname,
	}

	// Clear deadline for TLS handshake
	conn.SetDeadline(time.Time{})

	tlsConn := tls.Client(conn, tlsConf)
	if err := tlsConn.Handshake(); err != nil {
		return nil, notes, fmt.Errorf("TLS handshake failed after LDAP STARTTLS: %w", err)
	}

	state := tlsConn.ConnectionState()
	notes = append(notes, "LDAP STARTTLS upgrade successful — connection is now encrypted")

	return &state, notes, nil
}

// buildLDAPStartTLSRequest constructs a BER-encoded LDAP ExtendedRequest
// for the StartTLS OID (1.3.6.1.4.1.1466.20037).
func buildLDAPStartTLSRequest() []byte {
	// OID: 1.3.6.1.4.1.1466.20037 encoded as bytes
	oid := []byte("1.3.6.1.4.1.1466.20037")

	// Context-specific [0] tag for requestName in ExtendedRequest
	// Tag: 0x80 (context, primitive, tag 0)
	requestName := append([]byte{0x80, byte(len(oid))}, oid...)

	// ExtendedRequest: application tag [23] (0x77 = context, constructed, tag 23)
	extReq := append([]byte{0x77, byte(len(requestName))}, requestName...)

	// MessageID: INTEGER 1
	messageID := []byte{0x02, 0x01, 0x01} // INTEGER, length 1, value 1

	// LDAPMessage: SEQUENCE
	seqContent := append(messageID, extReq...)
	ldapMessage := append([]byte{0x30, byte(len(seqContent))}, seqContent...)

	return ldapMessage
}

// readLDAPStartTLSResponse reads the LDAP Extended Response and verifies
// that the server accepted the STARTTLS request (resultCode == 0 / success).
func readLDAPStartTLSResponse(conn net.Conn) error {
	// Read enough bytes for the response
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if n < 2 {
		return fmt.Errorf("response too short: %d bytes", n)
	}

	resp := buf[:n]

	// Very basic BER parsing:
	// SEQUENCE { MessageID INTEGER, ExtendedResponse [24] { resultCode ENUMERATED, ... } }
	//
	// We just need to find the resultCode. In practice, it's deeply nested:
	// 0x30 (SEQUENCE) -> 0x02 (INT, msgID) -> 0x78 (ExtendedResponse tag [24]) -> 0x0A (ENUM, resultCode)
	//
	// Simple approach: scan for the ENUMERATED tag (0x0A) after the ExtendedResponse tag (0x78)
	for i := 0; i < len(resp)-2; i++ {
		if resp[i] == 0x78 { // ExtendedResponse application tag
			// Find the ENUMERATED resultCode within
			for j := i + 2; j < len(resp)-2; j++ {
				if resp[j] == 0x0A { // ENUMERATED tag
					resultCodeLen := int(resp[j+1])
					if resultCodeLen > 0 && j+2 < len(resp) {
						resultCode := int(resp[j+2])
						if resultCode == 0 {
							return nil // Success!
						}
						return fmt.Errorf("server rejected STARTTLS with result code: %d", resultCode)
					}
				}
			}
		}
	}

	return fmt.Errorf("could not parse LDAP Extended Response (raw: %X)", resp)
}
