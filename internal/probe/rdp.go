package probe

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// RDP Protocol Constants for X.224 / TPKT negotiation
const (
	// TPKT header constants
	tpktVersion = 3
	tpktReserved = 0

	// X.224 Connection Request (CR) type
	x224TypeCR = 0xE0

	// X.224 Connection Confirm (CC) type
	x224TypeCC = 0xD0

	// RDP Negotiation Request type
	rdpNegReq = 0x01

	// RDP Negotiation Response type
	rdpNegResp = 0x02

	// Protocol flags
	protocolSSL    = 0x00000001
	protocolHybrid = 0x00000002
)

// probeRDP performs the RDP X.224 negotiation to upgrade to TLS and extract
// the connection state. This is the magic that makes `peep server:3389` work
// where `openssl s_client` would fail.
func probeRDP(target, hostname string, timeout time.Duration) (*tls.ConnectionState, []string, error) {
	var notes []string

	notes = append(notes, "RDP is the diva of protocols — it won't just show you its cert if you knock on the door. You have to ask nicely in X.224 first. That's why openssl s_client doesn't work here.")

	// Step 1: Open raw TCP connection
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.Dial("tcp", target)
	if err != nil {
		return nil, notes, fmt.Errorf("TCP connection to RDP service failed: %w", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout * 2)); err != nil {
		return nil, notes, fmt.Errorf("failed to set deadline: %w", err)
	}

	// Step 2: Build and send X.224 Connection Request with RDP Negotiation Request
	crPDU := buildRDPConnectionRequest()
	if _, err := conn.Write(crPDU); err != nil {
		return nil, notes, fmt.Errorf("failed to send X.224 Connection Request: %w", err)
	}

	notes = append(notes, "X.224 Connection Request sent (requesting TLS security)")

	// Step 3: Read X.224 Connection Confirm
	proto, err := readRDPConnectionConfirm(conn)
	if err != nil {
		return nil, notes, fmt.Errorf("failed to read X.224 Connection Confirm: %w", err)
	}

	if proto != protocolSSL && proto != protocolHybrid {
		notes = append(notes, "⚠️  Server did not agree to TLS — it may be using RDP Security Layer (legacy, less secure)")
		return nil, notes, fmt.Errorf("RDP server does not support TLS security (selected protocol: 0x%08X)", proto)
	}

	protoName := "PROTOCOL_SSL"
	if proto == protocolHybrid {
		protoName = "PROTOCOL_HYBRID (CredSSP/NLA)"
	}
	notes = append(notes, fmt.Sprintf("Server agreed to %s — upgrading to TLS", protoName))

	// Step 4: Perform TLS handshake over the existing connection
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         hostname,
	}

	// Clear the deadline for the TLS handshake — it has its own timeout
	conn.SetDeadline(time.Time{})

	tlsConn := tls.Client(conn, tlsConf)
	if err := tlsConn.Handshake(); err != nil {
		return nil, notes, fmt.Errorf("TLS handshake failed after X.224 negotiation: %w", err)
	}

	state := tlsConn.ConnectionState()
	notes = append(notes, "RDP TLS handshake successful — certificate extracted")

	return &state, notes, nil
}

// buildRDPConnectionRequest constructs an X.224 Connection Request PDU
// with an embedded RDP Negotiation Request for TLS security.
func buildRDPConnectionRequest() []byte {
	// RDP Negotiation Request structure (8 bytes):
	//   type(1) + flags(1) + length(2) + requestedProtocols(4)
	negReq := []byte{
		rdpNegReq,      // type: RDP_NEG_REQ
		0x00,           // flags
		0x08, 0x00,     // length: 8 (little-endian)
		0x03, 0x00, 0x00, 0x00, // requestedProtocols: PROTOCOL_SSL | PROTOCOL_HYBRID
	}

	// X.224 Connection Request:
	//   length indicator(1) + type(1) + dst-ref(2) + src-ref(2) + class(1) + cookie + negReq
	//
	// We'll use a minimal CR with no cookie, just the negotiation request.
	x224Header := []byte{
		0x00,   // length indicator (will be filled)
		x224TypeCR, // type: Connection Request
		0x00, 0x00, // destination reference
		0x00, 0x00, // source reference
		0x00,       // class and options
	}

	// Cookie: "Cookie: mstshash=peep\r\n"
	cookie := []byte("Cookie: mstshash=peep\r\n")

	// Calculate X.224 length indicator (everything after the length byte itself)
	x224Payload := append(x224Header[1:], cookie...)
	x224Payload = append(x224Payload, negReq...)
	x224Header[0] = byte(len(x224Payload))

	// Full X.224 data
	x224Data := append([]byte{x224Header[0]}, x224Payload...)

	// TPKT header (4 bytes): version(1) + reserved(1) + length(2, big-endian)
	tpktLen := uint16(4 + len(x224Data))
	tpkt := []byte{
		tpktVersion,
		tpktReserved,
		byte(tpktLen >> 8),
		byte(tpktLen & 0xFF),
	}

	return append(tpkt, x224Data...)
}

// readRDPConnectionConfirm reads and parses the X.224 Connection Confirm PDU.
// Returns the selected protocol from the RDP Negotiation Response.
func readRDPConnectionConfirm(conn net.Conn) (uint32, error) {
	// Read TPKT header (4 bytes)
	tpktHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, tpktHeader); err != nil {
		return 0, fmt.Errorf("failed to read TPKT header: %w", err)
	}

	if tpktHeader[0] != tpktVersion {
		return 0, fmt.Errorf("invalid TPKT version: %d (expected %d)", tpktHeader[0], tpktVersion)
	}

	// Get total length from TPKT
	tpktLen := int(binary.BigEndian.Uint16(tpktHeader[2:4]))
	if tpktLen < 4 {
		return 0, fmt.Errorf("invalid TPKT length: %d", tpktLen)
	}

	// Read the rest of the PDU
	payload := make([]byte, tpktLen-4)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return 0, fmt.Errorf("failed to read X.224 payload: %w", err)
	}

	if len(payload) < 1 {
		return 0, fmt.Errorf("empty X.224 payload")
	}

	// Parse X.224: first byte is length indicator, second is type
	// lengthIndicator := payload[0]
	if len(payload) < 2 {
		return 0, fmt.Errorf("X.224 payload too short")
	}

	x224Type := payload[1] & 0xF0 // Upper nibble is the type
	if x224Type != x224TypeCC {
		return 0, fmt.Errorf("unexpected X.224 PDU type: 0x%02X (expected Connection Confirm 0x%02X)", x224Type, x224TypeCC)
	}

	// Look for RDP Negotiation Response at the end of the payload
	// It's 8 bytes: type(1) + flags(1) + length(2) + selectedProtocol(4)
	// The negotiation response starts after the X.224 fixed header (7 bytes: LI + type + dst + src + class)
	if len(payload) < 7+8 {
		// No negotiation response — server may be using legacy RDP security
		return 0, fmt.Errorf("no RDP Negotiation Response in Connection Confirm — server may use legacy RDP security")
	}

	// Find the negotiation response (last 8 bytes of the payload)
	negResp := payload[len(payload)-8:]
	if negResp[0] != rdpNegResp {
		return 0, fmt.Errorf("unexpected negotiation type: 0x%02X (expected 0x%02X)", negResp[0], rdpNegResp)
	}

	selectedProtocol := binary.LittleEndian.Uint32(negResp[4:8])
	return selectedProtocol, nil
}
