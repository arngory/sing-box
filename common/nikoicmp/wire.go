package nikoicmp

import (
	"encoding/binary"
	"io"
	"net/netip"

	E "github.com/sagernet/sing/common/exceptions"
)

// The stream (raycontrol icmp-v1 §2): the tunnel's stream to Name:0, the version byte from the client, then frames
// both ways, numbers big-endian.
const (
	Name    = "icmp.niko.arpa"
	version = 1

	kindEcho         = 1 // client: echo request; server: echo reply
	kindTimeExceeded = 2
	kindUnreachable  = 3

	// unreachable, both families: the packet is larger than the node sends; the payload is a u16 MTU
	codeTooBig = 4

	// the largest echo data a frame carries
	maxPayload = 1452
)

// clientFrame: [kind 1][af 4|6][dst 4|16][ttl, 0 = 64][id][seq][len][payload].
func clientFrame(echo echoRequest) []byte {
	payload := echo.payload
	if len(payload) > maxPayload {
		payload = payload[:maxPayload]
	}
	dst := echo.destination.AsSlice()
	frame := make([]byte, 0, 2+len(dst)+7+len(payload))
	af := byte(4)
	if echo.destination.Is6() {
		af = 6
	}
	frame = append(frame, kindEcho, af)
	frame = append(frame, dst...)
	frame = append(frame, echo.ttl)
	frame = binary.BigEndian.AppendUint16(frame, echo.id)
	frame = binary.BigEndian.AppendUint16(frame, echo.seq)
	frame = binary.BigEndian.AppendUint16(frame, uint16(len(payload)))
	return append(frame, payload...)
}

// serverFrame: [kind][code][af][from 4|16][id][seq][len][payload].
type serverFrame struct {
	kind, code uint8
	from       netip.Addr
	id, seq    uint16
	payload    []byte
}

func readServerFrame(r io.Reader) (serverFrame, error) {
	var head [3]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return serverFrame{}, err
	}
	frame := serverFrame{kind: head[0], code: head[1]}
	if frame.kind < kindEcho || frame.kind > kindUnreachable {
		return serverFrame{}, E.New("icmp: unknown frame kind ", frame.kind)
	}
	var addr []byte
	switch head[2] {
	case 4:
		addr = make([]byte, 4)
	case 6:
		addr = make([]byte, 16)
	default:
		return serverFrame{}, E.New("icmp: unknown address family ", head[2])
	}
	if _, err := io.ReadFull(r, addr); err != nil {
		return serverFrame{}, err
	}
	frame.from, _ = netip.AddrFromSlice(addr)
	var rest [6]byte
	if _, err := io.ReadFull(r, rest[:]); err != nil {
		return serverFrame{}, err
	}
	frame.id = binary.BigEndian.Uint16(rest[0:2])
	frame.seq = binary.BigEndian.Uint16(rest[2:4])
	length := int(binary.BigEndian.Uint16(rest[4:6]))
	if length > maxPayload {
		return serverFrame{}, E.New("icmp: frame of ", length, " bytes")
	}
	frame.payload = make([]byte, length)
	if _, err := io.ReadFull(r, frame.payload); err != nil {
		return serverFrame{}, err
	}
	return frame, nil
}
