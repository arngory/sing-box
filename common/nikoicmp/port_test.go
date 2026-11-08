package nikoicmp

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
)

// an app's echo request as the TUN gives it
func request(t *testing.T, from, to netip.Addr, ttl uint8, id, seq uint16, data string) []byte {
	t.Helper()
	body := make([]byte, icmpHeader+len(data))
	if from.Is4() {
		body[0] = icmpv4EchoRequest
	} else {
		body[0] = icmpv6EchoRequest
	}
	binary.BigEndian.PutUint16(body[4:6], id)
	binary.BigEndian.PutUint16(body[6:8], seq)
	copy(body[icmpHeader:], data)
	packet := ipPacket(from, to, body)
	if from.Is4() {
		packet[8] = ttl
		binary.BigEndian.PutUint16(packet[10:12], 0)
		binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:ipv4HeaderMin], 0))
	} else {
		packet[7] = ttl
	}
	return packet
}

// valid: the IPv4 header's checksum and the ICMP checksum (with IPv6's pseudo-header) come out right
func valid(t *testing.T, packet []byte) {
	t.Helper()
	if packet[0]>>4 == 4 {
		if checksum(packet[:ipv4HeaderMin], 0) != 0 || checksum(packet[ipv4HeaderMin:], 0) != 0 {
			t.Fatalf("IPv4 checksums: % x", packet)
		}
		return
	}
	var pseudo uint32
	for i := 8; i < 40; i += 2 {
		pseudo += uint32(binary.BigEndian.Uint16(packet[i : i+2]))
	}
	pseudo += uint32(len(packet)-ipv6Header) + protocolICMPv6
	if checksum(packet[ipv6Header:], pseudo) != 0 {
		t.Fatalf("ICMPv6 checksum: % x", packet)
	}
}

func TestParseAndBuild(t *testing.T) {
	app4, dst4, hop4 := netip.MustParseAddr("172.19.0.1"), netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("203.0.113.9")
	packet := request(t, app4, dst4, 3, 7, 9, "ping")
	echo, ok := parseEcho(packet)
	if !ok || echo.source != app4 || echo.destination != dst4 || echo.ttl != 3 || echo.id != 7 || echo.seq != 9 ||
		string(echo.payload) != "ping" || !bytes.Equal(echo.quote, packet[:ipv4HeaderMin+icmpHeader]) {
		t.Fatalf("v4 echo: %+v %v", echo, ok)
	}
	frame := clientFrame(echo)
	want := append([]byte{kindEcho, 4, 1, 1, 1, 1, 3, 0, 7, 0, 9, 0, 4}, "ping"...)
	if !bytes.Equal(frame, want) {
		t.Fatalf("frame % x, want % x", frame, want)
	}
	reply := echoReply(dst4, app4, 7, 9, []byte("ping"))
	valid(t, reply)
	if reply[ipv4HeaderMin] != icmpv4EchoReply || !bytes.Equal(reply[ipv4HeaderMin+icmpHeader:], []byte("ping")) {
		t.Fatalf("v4 reply: % x", reply)
	}
	exceeded := errorMessage(hop4, app4, kindTimeExceeded, 0, 0, echo.quote)
	valid(t, exceeded)
	if exceeded[ipv4HeaderMin] != icmpv4TimeExceeded || !bytes.Equal(exceeded[ipv4HeaderMin+icmpHeader:], echo.quote) ||
		netip.AddrFrom4([4]byte(exceeded[12:16])) != hop4 {
		t.Fatalf("v4 time exceeded: % x", exceeded)
	}
	tooBig := errorMessage(hop4, app4, kindTooBig, 0, 1480, echo.quote)
	valid(t, tooBig)
	if tooBig[ipv4HeaderMin] != icmpv4Unreachable || tooBig[ipv4HeaderMin+1] != icmpv4FragNeeded ||
		binary.BigEndian.Uint16(tooBig[ipv4HeaderMin+6:]) != 1480 {
		t.Fatalf("v4 fragmentation needed: % x", tooBig)
	}

	app6, dst6, hop6 := netip.MustParseAddr("fdfe:dcba:9876::1"), netip.MustParseAddr("2606:4700::1111"), netip.MustParseAddr("2001:db8::9")
	packet = request(t, app6, dst6, 1, 1, 2, "v6")
	echo, ok = parseEcho(packet)
	if !ok || echo.source != app6 || echo.destination != dst6 || echo.ttl != 1 || string(echo.payload) != "v6" {
		t.Fatalf("v6 echo: %+v %v", echo, ok)
	}
	reply = echoReply(dst6, app6, 1, 2, []byte("v6"))
	valid(t, reply)
	if reply[ipv6Header] != icmpv6EchoReply {
		t.Fatalf("v6 reply: % x", reply)
	}
	tooBig = errorMessage(hop6, app6, kindTooBig, 0, 1500, echo.quote)
	valid(t, tooBig)
	if tooBig[ipv6Header] != icmpv6PacketTooBig || binary.BigEndian.Uint32(tooBig[ipv6Header+4:]) != 1500 {
		t.Fatalf("v6 packet too big: % x", tooBig)
	}
	// destination unreachable keeps its code: IPv6 4 is port unreachable, not too big
	portUnreachable := errorMessage(hop6, app6, kindUnreachable, 4, 0, echo.quote)
	valid(t, portUnreachable)
	if portUnreachable[ipv6Header] != icmpv6Unreachable || portUnreachable[ipv6Header+1] != 4 {
		t.Fatalf("v6 port unreachable: % x", portUnreachable)
	}
	hostUnreachable := errorMessage(hop4, app4, kindUnreachable, 1, 0, request(t, app4, dst4, 64, 1, 1, "x")[:28])
	valid(t, hostUnreachable)
	if hostUnreachable[ipv4HeaderMin] != icmpv4Unreachable || hostUnreachable[ipv4HeaderMin+1] != 1 {
		t.Fatalf("v4 host unreachable: % x", hostUnreachable)
	}
	prohibited := errorMessage(hop6, app6, kindUnreachable, 1, 0, echo.quote)
	valid(t, prohibited)
	if prohibited[ipv6Header] != icmpv6Unreachable || prohibited[ipv6Header+1] != 1 {
		t.Fatalf("v6 prohibited: % x", prohibited)
	}

	// not an echo request: an echo reply, UDP, a fragment, a cut packet
	if _, ok := parseEcho(reply); ok {
		t.Fatal("an echo reply was taken")
	}
	udp := request(t, app4, dst4, 64, 1, 1, "x")
	udp[9] = 17
	fragment := request(t, app4, dst4, 64, 1, 1, "x")
	fragment[6] = 0x20
	for _, p := range [][]byte{udp, fragment, request(t, app4, dst4, 64, 1, 1, "x")[:24]} {
		if _, ok := parseEcho(p); ok {
			t.Fatalf("taken: % x", p)
		}
	}
}

type collected struct {
	access  sync.Mutex
	packets [][]byte
	got     chan struct{}
}

func (c *collected) ReturnHeadroom() int { return 4 }

func (c *collected) ReturnPackets(packets [][]byte) [][]byte {
	c.access.Lock()
	for _, packet := range packets {
		c.packets = append(c.packets, packet[4:])
	}
	c.access.Unlock()
	c.got <- struct{}{}
	return nil
}

func (c *collected) wait(t *testing.T) []byte {
	t.Helper()
	select {
	case <-c.got:
	case <-time.After(5 * time.Second):
		t.Fatal("no packet back to the app")
	}
	c.access.Lock()
	defer c.access.Unlock()
	return c.packets[len(c.packets)-1]
}

// The port against a node of the wire: the version byte, the app's echo as a frame, the node's answers back to the
// app as IP packets.
func TestPortThroughTheNode(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	nodeSide := make(chan net.Conn, 1)
	port := NewPort(ctx, logger.NOP(), func(context.Context) (net.Conn, error) {
		client, node := net.Pipe()
		nodeSide <- node
		return client, nil
	})
	defer port.Close()
	back := &collected{got: make(chan struct{}, 8)}
	port.AttachReturn(back)

	app, dst, hop := netip.MustParseAddr("172.19.0.1"), netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("203.0.113.9")
	if err := port.WritePackets([][]byte{request(t, app, dst, 128, 7, 1, "first")}); err != nil {
		t.Fatal(err)
	}
	node := <-nodeSide
	head := make([]byte, 1)
	if _, err := io.ReadFull(node, head); err != nil || head[0] != version {
		t.Fatalf("version byte %v %v", head, err)
	}
	// the app's TTL above 64 goes as the node's own (0)
	frame := make([]byte, len(clientFrame(echoRequest{destination: dst, payload: []byte("first")})))
	if _, err := io.ReadFull(node, frame); err != nil || frame[6] != 0 || string(frame[13:]) != "first" {
		t.Fatalf("frame % x %v", frame, err)
	}
	answer := func(kind, code uint8, from netip.Addr, seq uint16, payload []byte) {
		b := []byte{kind, code, 4}
		b = append(b, from.AsSlice()...)
		b = binary.BigEndian.AppendUint16(b, 7)
		b = binary.BigEndian.AppendUint16(b, seq)
		b = binary.BigEndian.AppendUint16(b, uint16(len(payload)))
		node.Write(append(b, payload...))
	}
	answer(kindEcho, 0, dst, 1, []byte("first"))
	reply := back.wait(t)
	valid(t, reply)
	if reply[ipv4HeaderMin] != icmpv4EchoReply || netip.AddrFrom4([4]byte(reply[12:16])) != dst ||
		netip.AddrFrom4([4]byte(reply[16:20])) != app || string(reply[ipv4HeaderMin+icmpHeader:]) != "first" {
		t.Fatalf("echo reply % x", reply)
	}

	// traceroute: a probe with TTL 1, time exceeded from the first router, quoting the app's own packet
	probe := request(t, app, dst, 1, 7, 2, "probe")
	port.WritePackets([][]byte{probe})
	frame = make([]byte, len(clientFrame(echoRequest{destination: dst, payload: []byte("probe")})))
	if _, err := io.ReadFull(node, frame); err != nil || frame[6] != 1 {
		t.Fatalf("probe frame % x %v", frame, err)
	}
	answer(kindTimeExceeded, 0, hop, 2, nil)
	exceeded := back.wait(t)
	valid(t, exceeded)
	if exceeded[ipv4HeaderMin] != icmpv4TimeExceeded || netip.AddrFrom4([4]byte(exceeded[12:16])) != hop ||
		!bytes.Equal(exceeded[ipv4HeaderMin+icmpHeader:], probe[:ipv4HeaderMin+icmpHeader]) {
		t.Fatalf("time exceeded % x", exceeded)
	}
	// too big from a router behind the node: fragmentation needed with its MTU
	port.WritePackets([][]byte{request(t, app, dst, 64, 7, 3, "big")})
	frame = make([]byte, len(clientFrame(echoRequest{destination: dst, payload: []byte("big")})))
	if _, err := io.ReadFull(node, frame); err != nil {
		t.Fatal(err)
	}
	answer(kindTooBig, 0, hop, 3, []byte{0x05, 0x78})
	fragNeeded := back.wait(t)
	valid(t, fragNeeded)
	if fragNeeded[ipv4HeaderMin] != icmpv4Unreachable || fragNeeded[ipv4HeaderMin+1] != icmpv4FragNeeded ||
		binary.BigEndian.Uint16(fragNeeded[ipv4HeaderMin+6:]) != 1400 {
		t.Fatalf("fragmentation needed % x", fragNeeded)
	}
	// an echo longer than the node carries, without DF: unanswered, never "fragmentation needed and DF set"
	port.WritePackets([][]byte{request(t, app, dst, 64, 7, 4, string(make([]byte, maxPayload+1)))})
	select {
	case <-back.got:
		t.Fatal("a long echo without DF was answered with too big")
	case <-time.After(200 * time.Millisecond):
	}
	// with DF: too big at 1480 from the destination, answered here, nothing on the stream
	withDF := request(t, app, dst, 64, 7, 4, string(make([]byte, maxPayload+1)))
	withDF[6] |= 0x40
	binary.BigEndian.PutUint16(withDF[10:12], 0)
	binary.BigEndian.PutUint16(withDF[10:12], checksum(withDF[:ipv4HeaderMin], 0))
	port.WritePackets([][]byte{withDF})
	long := back.wait(t)
	valid(t, long)
	if long[ipv4HeaderMin+1] != icmpv4FragNeeded || binary.BigEndian.Uint16(long[ipv4HeaderMin+6:]) != maxPacket4 ||
		netip.AddrFrom4([4]byte(long[12:16])) != dst {
		t.Fatalf("too big for the stream % x", long)
	}
	// an answer to nothing asked is not passed on
	answer(kindEcho, 0, dst, 99, nil)
	select {
	case <-back.got:
		t.Fatal("an answer to no echo reached the app")
	case <-time.After(200 * time.Millisecond):
	}
	if !port.Available() {
		t.Fatal("unavailable while the node answers")
	}
}

// A node without ICMP for this user ends the stream at once: the port gives way to the TUN's own answers.
func TestPortRefused(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	port := NewPort(ctx, logger.NOP(), func(context.Context) (net.Conn, error) {
		client, node := net.Pipe()
		go func() {
			io.ReadFull(node, make([]byte, 1))
			node.Close()
		}()
		return client, nil
	})
	defer port.Close()
	port.WritePackets([][]byte{request(t, netip.MustParseAddr("172.19.0.1"), netip.MustParseAddr("1.1.1.1"), 64, 1, 1, "x")})
	deadline := time.Now().Add(5 * time.Second)
	for port.Available() {
		if time.Now().After(deadline) {
			t.Fatal("still available after the node refused")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
