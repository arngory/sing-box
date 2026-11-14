package conn

import (
	"net"
	"net/netip"
	"testing"

	"golang.org/x/net/ipv6"
)

// After a GSO attempt coalesced datagrams into one message and set its UDP_SEGMENT cmsg, the retry without GSO
// sends each datagram alone: one iovec, and no control data but the source's (none where setSrcControl does nothing).
func TestNekoSingleMessageAfterGSO(t *testing.T) {
	ep := &StdNetEndpoint{AddrPort: netip.MustParseAddrPort("192.0.2.1:51820")}
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 51820}
	bufs := [][]byte{make([]byte, 100), make([]byte, 100), make([]byte, 60)}
	msgs := make([]ipv6.Message, len(bufs))
	for i := range msgs {
		msgs[i].Buffers = make([][]byte, 1)
		msgs[i].OOB = make([]byte, 0, stickyControlSize+gsoControlSize)
	}
	n := coalesceMessages(addr, ep, bufs, 0, msgs, setGSOSize)
	if n != 1 || len(msgs[0].Buffers) != len(bufs) {
		t.Fatalf("coalesced into %d messages, the first of %d iovecs", n, len(msgs[0].Buffers))
	}
	gsoOOB := len(msgs[0].OOB)
	for i := range bufs {
		singleMessage(&msgs[i], bufs[i], addr, ep)
	}
	for i, msg := range msgs {
		if len(msg.Buffers) != 1 || len(msg.Buffers[0]) != len(bufs[i]) {
			t.Fatalf("message %d: %d iovecs of %d bytes after the reset", i, len(msg.Buffers), len(msg.Buffers[0]))
		}
		want := msg.OOB[:0]
		setSrcControl(&want, ep)
		if len(msg.OOB) != len(want) {
			t.Fatalf("message %d: %d bytes of control data, want %d (the GSO attempt left %d)", i, len(msg.OOB), len(want), gsoOOB)
		}
		if msg.Addr != addr {
			t.Fatalf("message %d: addressed to %v", i, msg.Addr)
		}
	}
}
