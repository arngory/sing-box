// Package nikoicmp carries an app's ICMP echo through a tunnel stream to the node, which pings for it
// (raycontrol icmp-v1): ping shows the real round trip, traceroute the hops behind the node.
package nikoicmp

import (
	"encoding/binary"
	"net/netip"
)

// echoRequest is an app's ICMP echo request as the TUN gave it.
type echoRequest struct {
	source, destination netip.Addr
	// the IP TTL or hop limit the app sent with: traceroute's probe
	ttl     uint8
	id, seq uint16
	payload []byte
	// the IP header and the first 8 bytes of ICMP: what an ICMP error to the app quotes
	quote []byte
}

const (
	icmpv4EchoRequest  = 8
	icmpv4EchoReply    = 0
	icmpv4Unreachable  = 3
	icmpv4TimeExceeded = 11
	icmpv4FragNeeded   = 4
	icmpv6EchoRequest  = 128
	icmpv6EchoReply    = 129
	icmpv6Unreachable  = 1
	icmpv6PacketTooBig = 2
	icmpv6TimeExceeded = 3
	protocolICMPv4     = 1
	protocolICMPv6     = 58
	ipv4HeaderMin      = 20
	ipv6Header         = 40
	icmpHeader         = 8
	replyTTL           = 64
)

// parseEcho reads an echo request out of an IPv4 or IPv6 packet (no IPv6 extension headers); false for anything else.
func parseEcho(packet []byte) (echoRequest, bool) {
	if len(packet) < ipv4HeaderMin {
		return echoRequest{}, false
	}
	switch packet[0] >> 4 {
	case 4:
		ihl := int(packet[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(packet[2:4]))
		if ihl < ipv4HeaderMin || total < ihl+icmpHeader || total > len(packet) || packet[9] != protocolICMPv4 {
			return echoRequest{}, false
		}
		// a fragment carries no whole echo
		if binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
			return echoRequest{}, false
		}
		icmp := packet[ihl:total]
		if icmp[0] != icmpv4EchoRequest || icmp[1] != 0 {
			return echoRequest{}, false
		}
		return echoRequest{
			source:      netip.AddrFrom4([4]byte(packet[12:16])),
			destination: netip.AddrFrom4([4]byte(packet[16:20])),
			ttl:         packet[8],
			id:          binary.BigEndian.Uint16(icmp[4:6]),
			seq:         binary.BigEndian.Uint16(icmp[6:8]),
			payload:     icmp[icmpHeader:],
			quote:       packet[:ihl+icmpHeader],
		}, true
	case 6:
		if len(packet) < ipv6Header+icmpHeader || packet[6] != protocolICMPv6 {
			return echoRequest{}, false
		}
		end := ipv6Header + int(binary.BigEndian.Uint16(packet[4:6]))
		if end > len(packet) || end < ipv6Header+icmpHeader {
			return echoRequest{}, false
		}
		icmp := packet[ipv6Header:end]
		if icmp[0] != icmpv6EchoRequest || icmp[1] != 0 {
			return echoRequest{}, false
		}
		return echoRequest{
			source:      netip.AddrFrom16([16]byte(packet[8:24])),
			destination: netip.AddrFrom16([16]byte(packet[24:40])),
			ttl:         packet[7],
			id:          binary.BigEndian.Uint16(icmp[4:6]),
			seq:         binary.BigEndian.Uint16(icmp[6:8]),
			payload:     icmp[icmpHeader:],
			quote:       packet[:ipv6Header+icmpHeader],
		}, true
	}
	return echoRequest{}, false
}

// echoReply is the reply to the app: from the destination, the app's own id, seq and data.
func echoReply(from, to netip.Addr, id, seq uint16, payload []byte) []byte {
	body := make([]byte, icmpHeader+len(payload))
	if from.Is4() {
		body[0] = icmpv4EchoReply
	} else {
		body[0] = icmpv6EchoReply
	}
	binary.BigEndian.PutUint16(body[4:6], id)
	binary.BigEndian.PutUint16(body[6:8], seq)
	copy(body[icmpHeader:], payload)
	return ipPacket(from, to, body)
}

// errorMessage is an ICMP error to the app from the router that sent it, with the app's own packet quoted (its IP
// header and first 8 bytes): time exceeded and destination unreachable with the code as it came; too big as IPv4
// fragmentation needed or IPv6 Packet Too Big, with the MTU.
func errorMessage(from, to netip.Addr, kind, code uint8, mtu uint16, quote []byte) []byte {
	body := make([]byte, icmpHeader+len(quote))
	if from.Is4() {
		switch kind {
		case kindTimeExceeded:
			body[0], body[1] = icmpv4TimeExceeded, code
		case kindTooBig:
			body[0], body[1] = icmpv4Unreachable, icmpv4FragNeeded
			binary.BigEndian.PutUint16(body[6:8], mtu)
		default:
			body[0], body[1] = icmpv4Unreachable, code
		}
	} else {
		switch kind {
		case kindTimeExceeded:
			body[0], body[1] = icmpv6TimeExceeded, code
		case kindTooBig:
			body[0] = icmpv6PacketTooBig
			binary.BigEndian.PutUint32(body[4:8], uint32(mtu))
		default:
			body[0], body[1] = icmpv6Unreachable, code
		}
	}
	copy(body[icmpHeader:], quote)
	return ipPacket(from, to, body)
}

// ipPacket wraps an ICMP message (its checksum still zero) in an IP header from the given addresses.
func ipPacket(from, to netip.Addr, icmp []byte) []byte {
	if from.Is4() {
		packet := make([]byte, ipv4HeaderMin+len(icmp))
		packet[0] = 0x45
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
		packet[8] = replyTTL
		packet[9] = protocolICMPv4
		src, dst := from.As4(), to.As4()
		copy(packet[12:16], src[:])
		copy(packet[16:20], dst[:])
		binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:ipv4HeaderMin], 0))
		copy(packet[ipv4HeaderMin:], icmp)
		binary.BigEndian.PutUint16(packet[ipv4HeaderMin+2:ipv4HeaderMin+4], checksum(packet[ipv4HeaderMin:], 0))
		return packet
	}
	packet := make([]byte, ipv6Header+len(icmp))
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(icmp)))
	packet[6] = protocolICMPv6
	packet[7] = replyTTL
	src, dst := from.As16(), to.As16()
	copy(packet[8:24], src[:])
	copy(packet[24:40], dst[:])
	copy(packet[ipv6Header:], icmp)
	// the ICMPv6 checksum covers a pseudo-header: both addresses, the length, the next header
	var pseudo uint32
	for i := 8; i < 40; i += 2 {
		pseudo += uint32(binary.BigEndian.Uint16(packet[i : i+2]))
	}
	pseudo += uint32(len(icmp)) + protocolICMPv6
	binary.BigEndian.PutUint16(packet[ipv6Header+2:ipv6Header+4], checksum(packet[ipv6Header:], pseudo))
	return packet
}

// checksum is the Internet checksum of b, started from initial.
func checksum(b []byte, initial uint32) uint16 {
	sum := initial
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
