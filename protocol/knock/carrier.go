package knock

import (
	"encoding/binary"
	"errors"
	"net"

	utls "github.com/metacubex/utls"
	"github.com/sagernet/sing-box/common/tls/chromehello"
)

// Carrier is how an SPA v2 packet reaches the node (spa-v2.md §10, §10.1).
type Carrier int32

const (
	// CarrierUDP: the packet as one datagram.
	CarrierUDP Carrier = iota
	// CarrierTLS: inside a ClientHello, as the ticket of its session_ticket extension (raycontrol v0.10.0+).
	CarrierTLS
	// CarrierTCP: the bare packet as the first data of a TCP connection (nodes before v0.10.0).
	CarrierTCP
)

// Carriers is the order to try them in: UDP, then the ClientHello, then bare TCP for older nodes.
var Carriers = []Carrier{CarrierUDP, CarrierTLS, CarrierTCP}

func (c Carrier) String() string {
	switch c {
	case CarrierTLS:
		return "tls"
	case CarrierTCP:
		return "tcp"
	default:
		return "udp"
	}
}

// network is the transport the carrier dials.
func (c Carrier) network() string {
	if c == CarrierUDP {
		return "udp"
	}
	return "tcp"
}

const extSessionTicket = 0x0023

// tlsCarrier wraps a sealed packet in a ClientHello record (spa-v2.md §10.1): the ClientHello of the core's
// Chrome reference (common/tls/chromehello), as Chrome sends it to an address (no server_name), with the packet
// as its session ticket. Random, session_id, key shares and GREASE are fresh, the extension order is shuffled.
func tlsCarrier(packet []byte) ([]byte, error) {
	spec, err := chromehello.Spec()
	if err != nil {
		return nil, err
	}
	conn, peer := net.Pipe()
	defer conn.Close()
	defer peer.Close()
	uConn := utls.UClient(conn, &utls.Config{InsecureSkipVerify: true}, utls.HelloCustom)
	if err = uConn.ApplyPreset(spec); err != nil {
		return nil, err
	}
	if err = uConn.BuildHandshakeStateWithoutSession(); err != nil {
		return nil, err
	}
	hello, err := withSessionTicket(uConn.HandshakeState.Hello.Raw, packet)
	if err != nil {
		return nil, err
	}
	record := []byte{0x16, 0x03, 0x01, byte(len(hello) >> 8), byte(len(hello))}
	return append(record, hello...), nil
}

// withSessionTicket returns the ClientHello handshake message with ticket as the data of its session_ticket
// extension (added at the end when the hello has none).
func withSessionTicket(hello, ticket []byte) ([]byte, error) {
	bad := errors.New("knock: not a ClientHello")
	if len(hello) < 4 || hello[0] != 0x01 {
		return nil, bad
	}
	body := hello[4:]
	at := 2 + 32
	skip := func(lenBytes int) bool {
		if len(body) < at+lenBytes {
			return false
		}
		n := 0
		for i := range lenBytes {
			n = n<<8 | int(body[at+i])
		}
		at += lenBytes + n
		return len(body) >= at
	}
	if !skip(1) || !skip(2) || !skip(1) || len(body) < at+2 {
		return nil, bad
	}
	fixed := body[:at]
	extensions := body[at+2:]
	if int(binary.BigEndian.Uint16(body[at:])) != len(extensions) {
		return nil, bad
	}
	var out []byte
	replaced := false
	for len(extensions) >= 4 {
		id := binary.BigEndian.Uint16(extensions)
		n := int(binary.BigEndian.Uint16(extensions[2:]))
		if len(extensions) < 4+n {
			return nil, bad
		}
		if id == extSessionTicket {
			out = binary.BigEndian.AppendUint16(out, extSessionTicket)
			out = binary.BigEndian.AppendUint16(out, uint16(len(ticket)))
			out = append(out, ticket...)
			replaced = true
		} else {
			out = append(out, extensions[:4+n]...)
		}
		extensions = extensions[4+n:]
	}
	if !replaced {
		out = binary.BigEndian.AppendUint16(out, extSessionTicket)
		out = binary.BigEndian.AppendUint16(out, uint16(len(ticket)))
		out = append(out, ticket...)
	}
	newBody := append(append([]byte(nil), fixed...), byte(len(out)>>8), byte(len(out)))
	newBody = append(newBody, out...)
	if len(newBody) > 0xffff {
		return nil, errors.New("knock: ClientHello too long")
	}
	return append([]byte{0x01, byte(len(newBody) >> 16), byte(len(newBody) >> 8), byte(len(newBody))}, newBody...), nil
}

// carrierPayload is what goes on the wire for the carrier.
func carrierPayload(c Carrier, packet []byte) ([]byte, error) {
	if c == CarrierTLS {
		return tlsCarrier(packet)
	}
	return packet, nil
}
